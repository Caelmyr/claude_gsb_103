"""告警通知订阅存储：订阅 CRUD、启停、条件匹配。

订阅以 JSON 文件持久化（data/notify/subscriptions.json），复用 storage 层的
进程内 RLock + flock + 原子替换，保证并发读写安全。

一条订阅描述「谁（owner）关心满足什么条件的告警，以及命中后推送到哪些渠道」：

- levels：风险等级白名单（低/中/高/严重），空列表表示不限制；
- rule_ids：规则 id 白名单，空列表表示不限制；
- event_types：事件类型白名单（login/transfer/...），空列表表示不限制；
- channels：渠道配置列表，支持 webhook 与 email；
- retry_max：推送失败后的最大重试次数（0 表示不重试）。
"""
import re
import threading
import time

from backend import config
from backend.storage import read_json, update_json, gen_id

CHANNEL_TYPES = ("webhook", "email")

_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class SubscriptionError(ValueError):
    """订阅参数校验错误。"""


def validate_channels(channels):
    """校验渠道配置，返回规范化后的列表；非法时抛 SubscriptionError。"""
    if not isinstance(channels, list) or not channels:
        raise SubscriptionError("至少配置一个推送渠道")
    out = []
    for ch in channels:
        if not isinstance(ch, dict):
            raise SubscriptionError("渠道配置必须是对象")
        ctype = ch.get("type")
        if ctype not in CHANNEL_TYPES:
            raise SubscriptionError(f"不支持的渠道类型：{ctype}")
        if ctype == "webhook":
            url = (ch.get("url") or "").strip()
            if not _URL_RE.match(url):
                raise SubscriptionError("Webhook 地址必须是合法的 http(s) URL")
            item = {"type": "webhook", "url": url}
            secret = (ch.get("secret") or "").strip()
            if secret:
                item["secret"] = secret
        else:
            to = (ch.get("to") or "").strip()
            if not _EMAIL_RE.match(to):
                raise SubscriptionError("邮件收件人地址不合法")
            item = {"type": "email", "to": to}
        out.append(item)
    return out


def _normalize_filters(body):
    """从请求体提取并校验过滤条件。"""
    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, str):
            value = [v.strip() for v in value.split(",") if v.strip()]
        if not isinstance(value, list):
            raise SubscriptionError("过滤条件必须是列表")
        return [str(v).strip() for v in value if str(v).strip()]

    levels = _as_list(body.get("levels"))
    valid_levels = set(config.DEFAULT_SETTINGS["alert"]["levels"])
    bad = [lv for lv in levels if lv not in valid_levels]
    if bad:
        raise SubscriptionError(f"非法风险等级：{'、'.join(bad)}")

    rule_ids = _as_list(body.get("rule_ids"))
    event_types = _as_list(body.get("event_types"))
    return levels, rule_ids, event_types


def build_subscription(body, owner, existing=None):
    """根据请求体构造（或更新）订阅字典，做完整校验。"""
    sub = dict(existing or {})
    name = (body.get("name") or "").strip()
    if not name:
        raise SubscriptionError("订阅名称不能为空")
    sub["name"] = name
    sub["owner"] = owner

    levels, rule_ids, event_types = _normalize_filters(body)
    sub["levels"] = levels
    sub["rule_ids"] = rule_ids
    sub["event_types"] = event_types

    if "channels" in body or not sub.get("channels"):
        sub["channels"] = validate_channels(body.get("channels"))

    retry_max = body.get("retry_max", sub.get("retry_max", 3))
    try:
        retry_max = int(retry_max)
    except (TypeError, ValueError):
        raise SubscriptionError("重试次数必须是 0~5 的整数")
    sub["retry_max"] = max(0, min(retry_max, 5))

    sub["enabled"] = bool(body.get("enabled", sub.get("enabled", True)))
    return sub


def matches(sub, alert, event=None):
    """判断告警是否满足订阅条件（订阅自身停用视为不匹配）。"""
    if not sub.get("enabled", True):
        return False
    levels = sub.get("levels") or []
    if levels and alert.get("level") not in levels:
        return False
    rule_ids = sub.get("rule_ids") or []
    if rule_ids and alert.get("rule_id") not in rule_ids:
        return False
    event_types = sub.get("event_types") or []
    if event_types:
        ev_type = (event or alert.get("event_sample") or {}).get("type")
        if ev_type not in event_types:
            return False
    return True


class SubscriptionStore:
    """订阅存储，所有变更走读-改-写原子落盘。"""

    def __init__(self, path=None):
        self.path = path or config.SUBSCRIPTIONS_FILE
        self._lock = threading.RLock()

    def _load(self):
        return read_json(self.path, {"subscriptions": []}).get("subscriptions", [])

    def _save(self, subs):
        atomic_write_json(self.path, {"subscriptions": subs})

    def list(self, owner=None):
        with self._lock:
            subs = self._load()
        if owner is not None:
            subs = [s for s in subs if s.get("owner") == owner]
        return subs

    def get(self, sub_id):
        for s in self._load():
            if s.get("id") == sub_id:
                return s
        return None

    def create(self, body, owner):
        sub = build_subscription(body, owner)
        with self._lock:
            def mutate(data):
                subs = data.setdefault("subscriptions", [])
                sub["id"] = gen_id("sub_")
                now = int(time.time())
                sub["created_at"] = now
                sub["updated_at"] = now
                subs.append(sub)
            update_json(self.path, mutate, default={"subscriptions": []})
        return sub

    def update(self, sub_id, body, owner, is_admin=False):
        """整单更新（名称/条件/渠道/重试）。仅属主或管理员可操作。"""
        with self._lock:
            def mutate(data):
                subs = data.setdefault("subscriptions", [])
                for i, s in enumerate(subs):
                    if s.get("id") == sub_id:
                        if s.get("owner") != owner and not is_admin:
                            raise PermissionError("无权修改他人的订阅")
                        merged = build_subscription(body, s.get("owner", owner), existing=s)
                        merged["updated_at"] = int(time.time())
                        subs[i] = merged
                        return merged
                raise KeyError(sub_id)
            try:
                return update_json(self.path, mutate, default={"subscriptions": []})
            except PermissionError:
                raise
            except KeyError:
                return None

    def set_enabled(self, sub_id, enabled, owner, is_admin=False):
        with self._lock:
            def mutate(data):
                for s in data.setdefault("subscriptions", []):
                    if s.get("id") == sub_id:
                        if s.get("owner") != owner and not is_admin:
                            raise PermissionError("无权操作他人的订阅")
                        s["enabled"] = bool(enabled)
                        s["updated_at"] = int(time.time())
                        return s
                return None
            try:
                return update_json(self.path, mutate, default={"subscriptions": []})
            except PermissionError:
                raise

    def delete(self, sub_id, owner, is_admin=False):
        with self._lock:
            def mutate(data):
                subs = data.setdefault("subscriptions", [])
                for s in subs:
                    if s.get("id") == sub_id and (s.get("owner") == owner or is_admin):
                        data["subscriptions"] = [x for x in subs if x.get("id") != sub_id]
                        return True
                return False
            return update_json(self.path, mutate, default={"subscriptions": []})

    def matching(self, alert, event=None):
        """返回所有命中的启用订阅。"""
        return [s for s in self._load() if matches(s, alert, event)]
