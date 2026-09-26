"""通知调度器：监听引擎新告警 → 匹配订阅 → 后台推送 → 有限次指数退避重试。

设计要点：
1. 作为引擎监听器（engine.add_listener）接收广播，仅对 ``created=True`` 的
   新建告警触发推送——去重累加的告警不重复通知，天然配合告警聚合去重；
2. 每条「订阅 × 渠道」生成一条 delivery 记录并持久化，随后放入优先队列由
   单工作线程异步发送，不阻塞事件处理主链路；
3. 发送失败按 10s / 30s / 60s … 指数退避重试（上限由订阅 retry_max 决定，0~5 次），
   超过次数置为终态 failed 并保留错误信息；进程重启后从当天/前一天分片恢复未完成记录；
4. 渠道：Webhook（urllib POST JSON，可配 HMAC-SHA256 签名）、邮件（smtplib/SMTP）；
   外发实现与调度逻辑分离，便于在测试中替换为内存假渠道。
"""
import collections
import hashlib
import hmac
import json
import smtplib
import threading
import time
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

from backend.settings_store import get_settings
from backend.notify.subscription_store import SubscriptionStore
from backend.notify.delivery_store import (
    DeliveryStore, STATUS_SUCCESS, STATUS_RETRYING, STATUS_FAILED,
)

# 退避基数与上限（秒）
_BACKOFF_BASE = 10
_BACKOFF_CAP = 300
# Webhook 请求超时（秒）
HTTP_TIMEOUT = 5
# 去重护栏保留时长与容量（防止同一告警被重复入队）
_GUARD_TTL = 3600
_GUARD_MAX = 10000


def backoff_delay(attempts):
    """第 attempts 次发送失败后的退避秒数（attempts 从 1 开始）。"""
    return min(_BACKOFF_BASE * 2 ** max(0, attempts - 1), _BACKOFF_CAP)


# ---------------------------------------------------------------------------
# 渠道发送器：返回 (ok, error)
# ---------------------------------------------------------------------------
def send_webhook(channel, payload):
    url = channel["url"]
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "risk-engine-notifier/1.0",
    })
    secret = channel.get("secret")
    if secret:
        digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        req.add_header("X-Signature", "sha256=" + digest)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            code = resp.getcode()
            if code >= 400:
                return False, f"Webhook 返回 HTTP {code}"
            return True, ""
    except urllib.error.HTTPError as e:
        return False, f"Webhook 返回 HTTP {e.code}"
    except Exception as e:
        return False, f"Webhook 请求异常：{e}"


def send_email(channel, payload):
    cfg = (get_settings() or {}).get("notification", {}).get("smtp", {})
    host = cfg.get("host")
    if not host:
        return False, "未配置 SMTP 服务器（请在系统设置中配置 notification.smtp）"
    alert = payload.get("alert", {})
    level = alert.get("level", "中")
    subject = f"【风控告警通知】[{level}] {alert.get('rule_name') or alert.get('rule_id')}"
    lines = [
        "您订阅的风控规则命中了新告警：",
        "",
        f"告警 ID：{alert.get('id')}",
        f"规则：{alert.get('rule_name')}（{alert.get('rule_id')}）",
        f"等级：{level}    风险分：{alert.get('risk_score')}",
        f"动作：{alert.get('action')}",
        f"主体：{json.dumps(alert.get('subject', {}), ensure_ascii=False)}",
        f"时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.get('ts') or time.time()))}",
        "",
        "事件样本：",
        json.dumps(alert.get('event_sample', {}), ensure_ascii=False, indent=2),
    ]
    msg = MIMEText("\n".join(lines), "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    from_addr = cfg.get("from") or cfg.get("username") or "risk-engine@localhost"
    msg["From"] = formataddr((str(Header("风控引擎", "utf-8")), from_addr))
    msg["To"] = channel["to"]
    port = int(cfg.get("port", 25))
    use_tls = bool(cfg.get("use_tls", port == 465))
    timeout = float(cfg.get("timeout", 10))
    try:
        if use_tls and port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        try:
            server.ehlo()
            if use_tls and port != 465:
                server.starttls()
                server.ehlo()
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.sendmail(from_addr, [channel["to"]], msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                server.close()
        return True, ""
    except Exception as e:
        return False, f"邮件发送异常：{e}"


_SENDERS = {"webhook": send_webhook, "email": send_email}


def build_payload(record):
    """根据推送记录构造外发报文（首次与重试使用同一内容）。"""
    return {
        "source": "risk-engine",
        "type": "risk_alert",
        "ts": int(time.time()),
        "subscription": {"id": record.get("sub_id"), "name": record.get("sub_name")},
        "alert": record.get("alert", {}),
    }


class Notifier:
    """通知调度器（线程安全；工作线程为守护线程）。"""

    def __init__(self, engine=None, store=None, deliveries=None, senders=None):
        self.engine = engine
        self.store = store or SubscriptionStore()
        self.deliveries = deliveries or DeliveryStore()
        self._senders = dict(senders or _SENDERS)
        self._queue = []                # [(run_at, seq, delivery_id)]
        self._queued = set()            # 已在队列中的 delivery_id
        self._seq = 0
        self._cond = threading.Condition()
        self._guard = collections.OrderedDict()   # key -> expire_ts
        self._attached = False
        self._stopped = False
        self._worker = threading.Thread(target=self._run, name="notifier", daemon=True)
        self._worker.start()
        self._recover()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def attach(self, engine):
        if self._attached:
            return
        self.engine = engine
        engine.add_listener(self.on_engine_message)
        self._attached = True

    def detach(self):
        if self.engine is not None and self._attached:
            self.engine.remove_listener(self.on_engine_message)
        self._attached = False

    def stop(self):
        with self._cond:
            self._stopped = True
            self._cond.notify_all()

    def _recover(self):
        """进程重启后恢复未完成的推送记录，按剩余退避时间重新入队。"""
        n = 0
        for r in self.deliveries.recoverable():
            with self._cond:
                if r["id"] not in self._queued:
                    self._enqueue_locked(r["id"], r.get("next_retry_at") or time.time())
                    n += 1
        return n

    # ------------------------------------------------------------------
    # 引擎事件入口
    # ------------------------------------------------------------------
    def on_engine_message(self, message):
        if not self._attached:
            return
        try:
            if not isinstance(message, dict) or message.get("kind") != "event":
                return
            decision = message.get("decision") or {}
            event = message.get("event") or {}
            details = {d.get("rule_id"): d for d in decision.get("fired_rules", [])}
            for ar in decision.get("alerts", []):
                if not ar.get("created"):
                    continue
                detail = details.get(ar.get("rule_id"), {})
                alert = {
                    "id": ar.get("alert_id"),
                    "rule_id": ar.get("rule_id"),
                    "rule_name": detail.get("rule_name"),
                    "reason": detail.get("reason"),
                    "level": ar.get("level"),
                    "risk_score": detail.get("risk_score"),
                    "action": detail.get("action"),
                    "subject": ar.get("subject", {}),
                    "count": ar.get("count", 1),
                    "status": "new",
                    "ts": decision.get("ts") or event.get("ts") or time.time(),
                    "event_sample": event,
                }
                self.dispatch_alert(alert, event)
        except Exception:
            # 通知异常绝不能影响引擎主链路
            pass

    def dispatch_alert(self, alert, event=None):
        """对一条新建告警匹配全部订阅并入队推送，返回创建的 delivery 数。"""
        created = 0
        for sub in self.store.matching(alert, event):
            for channel in sub.get("channels", []):
                key = (sub.get("id"), channel.get("type"),
                       channel.get("url") or channel.get("to"), alert.get("id"))
                if not self._guard_acquire(key):
                    continue
                record = self.deliveries.create(
                    sub, channel, self._snapshot(alert), sub.get("retry_max", 3))
                with self._cond:
                    self._enqueue_locked(record["id"], time.time())
                created += 1
        return created

    def _snapshot(self, alert):
        """投递记录中保存的告警快照（剔除过大字段中的冗余，保留事件样本）。"""
        snap = dict(alert)
        ev = snap.get("event_sample")
        if isinstance(ev, dict) and len(ev) > 50:
            snap["event_sample"] = dict(list(ev.items())[:50])
        return snap

    def _guard_acquire(self, key):
        """去重护栏：同一 订阅+渠道+告警 在 TTL 内只入队一次。"""
        now = time.time()
        with self._cond:
            old = self._guard.get(key)
            self._guard[key] = now + _GUARD_TTL
            self._guard.move_to_end(key)
            while len(self._guard) > _GUARD_MAX:
                self._guard.popitem(last=False)
            # 顺带惰性清理过期项
            for k, exp in list(self._guard.items()):
                if exp <= now:
                    self._guard.pop(k, None)
                else:
                    break
            return old is None or old <= now

    # ------------------------------------------------------------------
    # 队列与工作线程
    # ------------------------------------------------------------------
    def _enqueue_locked(self, delivery_id, run_at):
        if delivery_id in self._queued:
            return
        self._seq += 1
        self._queue.append((run_at, self._seq, delivery_id))
        self._queue.sort()
        self._queued.add(delivery_id)
        self._cond.notify_all()

    def _run(self):
        while True:
            with self._cond:
                if self._stopped:
                    return
                if not self._queue:
                    self._cond.wait(timeout=5)
                    continue
                run_at, _, delivery_id = self._queue[0]
                wait = run_at - time.time()
                if wait > 0:
                    self._cond.wait(timeout=min(wait, 5))
                    continue
                self._queue.pop(0)
                self._queued.discard(delivery_id)
            self._deliver(delivery_id)

    def _channel_from_record(self, record):
        """发送时解析渠道配置：优先取订阅中的最新配置（含 secret），
        订阅已删除时退化为投递记录中保存的目标地址。"""
        fallback_target = record.get("channel_target", "")
        ctype = record.get("channel_type")
        sub = self.store.get(record.get("sub_id") or "")
        if sub:
            for ch in sub.get("channels", []):
                if ch.get("type") == ctype:
                    if ctype == "webhook" and ch.get("url") == fallback_target:
                        return ch
                    if ctype == "email" and ch.get("to") == fallback_target:
                        return ch
        if ctype == "webhook":
            return {"type": "webhook", "url": fallback_target}
        return {"type": "email", "to": fallback_target}

    def _deliver(self, delivery_id):
        record = self.deliveries.get(delivery_id)
        if record is None:
            return
        channel = self._channel_from_record(record)
        sender = self._senders.get(channel["type"])
        if sender is None:
            self.deliveries.update_result(delivery_id, STATUS_FAILED,
                                          error=f"未知渠道类型：{channel['type']}")
            return
        ok, error = sender(channel, build_payload(record))
        if ok:
            self.deliveries.update_result(delivery_id, STATUS_SUCCESS)
            return
        attempts = record.get("attempts", 0) + 1
        if attempts >= record.get("max_attempts", 1):
            self.deliveries.update_result(delivery_id, STATUS_FAILED, error=error)
            return
        next_at = time.time() + backoff_delay(attempts)
        self.deliveries.update_result(delivery_id, STATUS_RETRYING,
                                      error=error, next_retry_at=next_at)
        with self._cond:
            self._enqueue_locked(delivery_id, next_at)

    # ------------------------------------------------------------------
    # 手动测试推送（同步发送，不落历史）
    # ------------------------------------------------------------------
    def test_channel(self, channel):
        payload = {
            "source": "risk-engine",
            "type": "risk_alert.test",
            "ts": int(time.time()),
            "subscription": {"id": None, "name": "渠道连通性测试"},
            "alert": {
                "id": "test",
                "rule_name": "测试告警",
                "rule_id": "test",
                "level": "高",
                "risk_score": 80,
                "action": "alert",
                "subject": {"ip": "127.0.0.1"},
                "count": 1,
                "ts": time.time(),
                "event_sample": {"type": "test", "message": "这是一条测试通知"},
            },
        }
        sender = self._senders.get(channel.get("type"))
        if sender is None:
            return False, f"未知渠道类型：{channel.get('type')}"
        ok, error = sender(channel, payload)
        return ok, error
