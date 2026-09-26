"""告警通知推送：订阅匹配、渠道发送、失败有限次重试。

设计要点：
1. 引擎在产生「新建」告警（非去重累加）后调用 :meth:`NotifierService.on_alert`，
   与每条启用订阅做条件匹配（等级 / 规则 / 事件类型，多条件之间为 AND，
   空条件表示不限制）；
2. 匹配命中即生成一条 delivery 记录（pending）落盘，并放入后台发送队列，
   引擎主链路不被网络 IO 阻塞；
3. 单个 daemon worker 串行发送，支持 Webhook（POST JSON，可选 HMAC-SHA256
   签名头）与邮件（SMTP，全局配置）两种渠道；
4. 失败按指数退避有限次重试（次数由系统设置 notify.max_retries 控制），
   每次尝试（含 HTTP 状态、耗时、错误）都记录在 delivery.attempts 中；
5. 进程重启时，落盘为 pending 的记录会被恢复并重试一次，避免崩溃丢通知。
"""
import base64
import hashlib
import hmac
import json
import queue
import smtplib
import socket
import threading
import time
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from backend.settings_store import get_settings
from backend.storage import gen_id
from backend.notify.store import SubscriptionStore, DeliveryStore


def match_subscription(sub, alert, event):
    """判断告警是否符合订阅条件（各非空条件之间为 AND）。"""
    levels = sub.get("levels") or []
    if levels and alert.get("level") not in levels:
        return False

    rule_ids = sub.get("rule_ids") or []
    if rule_ids and alert.get("rule_id") not in rule_ids:
        return False

    event_types = sub.get("event_types") or []
    if event_types:
        ev_type = (event or {}).get("type")
        if ev_type not in event_types:
            return False
    return True


class NotifierService:
    def __init__(self, settings=None, subscription_store=None, delivery_store=None):
        self.settings = settings or get_settings()
        self.subscriptions = subscription_store or SubscriptionStore()
        self.deliveries = delivery_store or DeliveryStore()

        self._queue = queue.Queue()
        self._wakeup = threading.Event()
        self._worker = None
        self._started = False
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def start(self):
        with self._lock:
            if self._started:
                return
            self._started = True
            self._worker = threading.Thread(
                target=self._run, name="notify-worker", daemon=True)
            self._worker.start()
            self._recover_pending()

    def stop(self):
        with self._lock:
            if not self._started:
                return
            self._started = False
        self._wakeup.set()
        self._queue.put(None)

    def _recover_pending(self):
        """重启恢复：上次崩溃时仍 pending 的记录重新入队。"""
        for d in self.deliveries.pending():
            sub = self.subscriptions.get(d.get("subscription_id", ""))
            if sub is None or not sub.get("enabled", True):
                self.deliveries.update(d["id"], status="failed",
                                       last_error="订阅已删除或停用，放弃发送")
                continue
            self._enqueue(d["id"], sub, delay=1.0, recovered=True)

    # ------------------------------------------------------------------
    # 引擎入口
    # ------------------------------------------------------------------
    def on_alert(self, alert, event, decision=None):
        """告警产生时调用；对每条命中的启用订阅创建推送任务。"""
        if not self._started:
            self.start()
        tasks = []
        for sub in self.subscriptions.list(enabled_only=True):
            try:
                hit = match_subscription(sub, alert, event or {})
            except Exception:
                hit = False
            if not hit:
                continue
            delivery = self._new_delivery(sub, alert, event, decision)
            self.deliveries.add(delivery)
            self._enqueue(delivery["id"], sub, delay=0.0)
            tasks.append(delivery["id"])
        return tasks

    def _new_delivery(self, sub, alert, event, decision):
        now = time.time()
        payload = self.build_payload(alert, event, decision, sub)
        return {
            "id": gen_id("dlv_"),
            "subscription_id": sub["id"],
            "subscription_name": sub.get("name", ""),
            "owner": sub.get("owner", ""),
            "channel": sub.get("channel", "webhook"),
            "target": sub.get("target", ""),
            "alert_id": alert.get("id"),
            "alert_level": alert.get("level"),
            "rule_id": alert.get("rule_id"),
            "rule_name": alert.get("rule_name") or alert.get("reason"),
            "status": "pending",
            "attempts": [],
            "retries_left": int(self._cfg().get("max_retries", 3)),
            "created_at": now,
            "updated_at": now,
            "last_error": "",
            "request_payload": payload,
        }

    def build_payload(self, alert, event, decision=None, sub=None):
        """构造推送给渠道的告警内容（Webhook JSON / 邮件正文共用）。"""
        return {
            "title": f"[{alert.get('level', '中')}] {alert.get('rule_name') or alert.get('reason', '告警')}",
            "alert_id": alert.get("id"),
            "level": alert.get("level"),
            "risk_score": alert.get("risk_score"),
            "rule_id": alert.get("rule_id"),
            "rule_name": alert.get("rule_name") or alert.get("reason"),
            "subject": alert.get("subject", {}),
            "count": alert.get("count", 1),
            "status": alert.get("status", "new"),
            "event": event or alert.get("event_sample", {}),
            "first_seen": alert.get("first_seen"),
            "last_seen": alert.get("last_seen"),
            "ts": int(time.time()),
            "source": "risk-engine",
        }

    # ------------------------------------------------------------------
    # 手动测试
    # ------------------------------------------------------------------
    def test_subscription(self, sub):
        """立即同步发送一条测试通知，返回 (ok, error, attempt)。"""
        fake_alert = {
            "id": f"test_{int(time.time())}",
            "rule_id": "test",
            "rule_name": "测试告警",
            "level": (sub.get("levels") or ["高"])[0],
            "risk_score": 80,
            "subject": {"test": True},
            "count": 1,
            "status": "new",
            "first_seen": time.time(),
            "last_seen": time.time(),
        }
        payload = self.build_payload(fake_alert, {"type": "test", "id": "evt_test"}, sub=sub)
        payload["test"] = True
        return self._send(sub, payload)

    # ------------------------------------------------------------------
    # 队列 / worker
    # ------------------------------------------------------------------
    def _cfg(self):
        # 发送时实时读取设置，便于调整重试参数/SMTP 后即时生效
        return get_settings().get("notify", {})

    def _enqueue(self, delivery_id, sub_snapshot, delay=0.0, recovered=False):
        self._queue.put((delivery_id, dict(sub_snapshot), max(0.0, delay), recovered))
        self._wakeup.set()

    def _run(self):
        pending_delays = []  # 最小堆：(fire_at, delivery_id, sub_snapshot, recovered)
        import heapq
        while self._started:
            timeout = None
            now = time.time()
            while pending_delays and pending_delays[0][0] <= now:
                _, dlv_id, sub_snap, recovered = heapq.heappop(pending_delays)
                self._queue.put((dlv_id, sub_snap, 0.0, recovered))
            if pending_delays:
                timeout = max(0.0, pending_delays[0][0] - time.time())

            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                continue
            if item is None:
                break
            dlv_id, sub_snap, delay, recovered = item
            if delay > 0:
                heapq.heappush(pending_delays,
                               (time.time() + delay, dlv_id, sub_snap, recovered))
                continue
            try:
                self._deliver(dlv_id, sub_snap, recovered)
            except Exception as exc:  # 兜底：worker 不能因单条任务挂掉
                self.deliveries.update(dlv_id, status="failed",
                                       last_error=f"发送异常：{exc}",
                                       updated_at=time.time())

    def _deliver(self, delivery_id, sub, recovered=False):
        delivery = None
        for d in self.deliveries.list(limit=1000):
            if d.get("id") == delivery_id:
                delivery = d
                break
        if delivery is None:
            return
        if delivery.get("status") == "success":
            return

        payload = delivery.get("request_payload") or {}
        ok, error, attempt = self._send(sub, payload)
        attempts = list(delivery.get("attempts", []))
        if recovered:
            attempt["note"] = "进程重启后恢复发送"
        attempts.append(attempt)

        if ok:
            self.deliveries.update(
                delivery_id, status="success", last_error="",
                attempts=attempts, updated_at=time.time())
            return

        retries_left = int(delivery.get("retries_left", 0)) - 1
        if retries_left > 0 and self._started and sub.get("enabled", True):
            base = int(self._cfg().get("retry_backoff_base", 5) or 5)
            delay = base * (2 ** (len(attempts) - 1))  # 5s, 10s, 20s ...
            self.deliveries.update(
                delivery_id, status="pending", retries_left=retries_left,
                last_error=error, attempts=attempts, updated_at=time.time())
            self._enqueue(delivery_id, sub, delay=delay)
        else:
            self.deliveries.update(
                delivery_id, status="failed", retries_left=0,
                last_error=error, attempts=attempts, updated_at=time.time())

    # ------------------------------------------------------------------
    # 渠道发送（返回 ok, error, attempt_dict）
    # ------------------------------------------------------------------
    def _send(self, sub, payload):
        channel = sub.get("channel", "webhook")
        started = time.time()
        try:
            if channel == "webhook":
                detail = self._send_webhook(sub, payload)
            elif channel == "email":
                detail = self._send_email(sub, payload)
            else:
                detail = {"status": "error", "error": f"未知渠道：{channel}"}
        except Exception as exc:
            detail = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

        attempt = {
            "ts": started,
            "elapsed_ms": int((time.time() - started) * 1000),
            "channel": channel,
            "target": sub.get("target", ""),
        }
        attempt.update(detail)
        ok = detail.get("status") == "ok"
        return ok, detail.get("error", ""), attempt

    def _send_webhook(self, sub, payload):
        cfg = self._cfg()
        timeout = int(cfg.get("timeout_sec", 5) or 5)
        url = sub["target"]
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8",
                   "User-Agent": "risk-engine-notifier/1.0"}
        secret = sub.get("secret") or ""
        if secret:
            digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
            headers["X-Signature-SHA256"] = "sha256=" + base64.b64encode(digest).decode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                resp.read(2048)
                if 200 <= code < 300:
                    return {"status": "ok", "http_status": code}
                return {"status": "error", "http_status": code,
                        "error": f"Webhook 返回非成功状态码 {code}"}
        except urllib.error.HTTPError as exc:
            snippet = ""
            try:
                snippet = exc.read(512).decode("utf-8", "ignore")
            except Exception:
                pass
            return {"status": "error", "http_status": exc.code,
                    "error": f"HTTP {exc.code} {snippet[:200]}"}
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            return {"status": "error", "error": f"网络错误：{exc.reason if isinstance(exc, urllib.error.URLError) else exc}"}

    def _send_email(self, sub, payload):
        cfg = self._cfg()
        smtp_cfg = cfg.get("smtp", {})
        host = smtp_cfg.get("host", "")
        if not host:
            return {"status": "error", "error": "未配置 SMTP 服务器（请在通知设置中配置）"}
        port = int(smtp_cfg.get("port", 465) or 465)
        timeout = int(cfg.get("timeout_sec", 5) or 5)
        username = smtp_cfg.get("username", "")
        password = smtp_cfg.get("password", "")
        from_addr = smtp_cfg.get("from_addr", "") or username
        if not from_addr:
            return {"status": "error", "error": "SMTP 发件人/用户名未配置"}

        subject_text = f"[风控告警] {payload.get('title', '新告警')}"
        text_lines = [
            subject_text,
            f"告警ID：{payload.get('alert_id')}",
            f"规则：{payload.get('rule_name')}（{payload.get('rule_id')}）",
            f"等级：{payload.get('level')}    风险分：{payload.get('risk_score')}",
            f"主体：{json.dumps(payload.get('subject', {}), ensure_ascii=False)}",
            f"聚合次数：{payload.get('count')}    状态：{payload.get('status')}",
            f"时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload.get('ts') or time.time()))}",
            "",
            "事件原文：",
            json.dumps(payload.get("event", {}), ensure_ascii=False, indent=2),
        ]

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject_text
        msg["From"] = formataddr(("风控引擎", from_addr))
        msg["To"] = sub["target"]
        msg.attach(MIMEText("\n".join(text_lines), "plain", "utf-8"))
        msg.attach(MIMEText(
            f"<pre style='font-family:monospace'>{self._html_escape(chr(10).join(text_lines))}</pre>",
            "html", "utf-8"))

        use_ssl = bool(smtp_cfg.get("ssl", True))
        socket.setdefaulttimeout(timeout)
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        try:
            server.ehlo()
            if not use_ssl and port == 587:
                server.starttls()
                server.ehlo()
            if username:
                server.login(username, password)
            server.sendmail(from_addr, [a.strip() for a in sub["target"].split(",") if a.strip()],
                            msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return {"status": "ok"}

    @staticmethod
    def _html_escape(text):
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))
