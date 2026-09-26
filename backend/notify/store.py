"""通知订阅与推送历史存储。

数据文件（JSON，复用 storage 的原子读写）：
- data/notify/subscriptions.json: {"subscriptions": [...]}
- data/notify/deliveries.json:    {"deliveries": [...]}

订阅文件很小，全量读-改-写即可；为避免每条告警都触发磁盘 IO，读取侧使用
「文件 mtime + 内容缓存」，仅在文件被其他进程改动后才重新解析。推送历史按
订阅裁剪条数与保留天数，防止无限增长。
"""
import os
import threading
import time

from backend import config
from backend.storage import (
    atomic_write_json, read_json, update_json, gen_id,
)

# 渠道与状态枚举
CHANNELS = ("webhook", "email")
DELIVERY_STATUSES = ("pending", "success", "failed")

_VALID_LEVELS = ("低", "中", "高", "严重")


# ---------------------------------------------------------------------------
# 订阅结构校验 / 规范化
# ---------------------------------------------------------------------------
def _as_str_list(value):
    """把逗号分隔字符串或列表规整为去重后的字符串列表。"""
    if value is None:
        return []
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    out = []
    for v in value:
        if v is None:
            continue
        v = str(v).strip()
        if v and v not in out:
            out.append(v)
    return out


def validate_subscription(body):
    """校验订阅表单，返回 (subscription_dict, error)。"""
    name = str(body.get("name", "")).strip()
    channel = body.get("channel", "webhook")
    target = str(body.get("target", "")).strip()
    if not name:
        return None, "订阅名称不能为空"
    if channel not in CHANNELS:
        return None, f"渠道仅支持：{', '.join(CHANNELS)}"
    if channel == "email":
        # 支持逗号分隔的多个收件人，容忍逗号后的空格
        target = ",".join(p.strip() for p in target.split(",") if p.strip())
    if not target:
        return None, "Webhook 地址不能为空" if channel == "webhook" else "收件邮箱不能为空"
    if channel == "webhook" and not target.lower().startswith(("http://", "https://")):
        return None, "Webhook 地址必须以 http:// 或 https:// 开头"
    if channel == "email":
        recipients = [p for p in target.split(",") if p]
        if not recipients or any("@" not in p or " " in p for p in recipients):
            return None, "收件邮箱格式不正确（多个邮箱请用英文逗号分隔）"

    levels = _as_str_list(body.get("levels"))
    for lv in levels:
        if lv not in _VALID_LEVELS:
            return None, f"非法告警等级：{lv}"

    sub = {
        "name": name,
        "channel": channel,
        "target": target,
        "secret": str(body.get("secret", "") or ""),
        "levels": levels,
        "rule_ids": _as_str_list(body.get("rule_ids")),
        "event_types": _as_str_list(body.get("event_types")),
        "enabled": bool(body.get("enabled", True)),
        "remark": str(body.get("remark", "") or ""),
    }
    return sub, None


def merge_subscription(old, patch):
    """用 patch 更新已有订阅（仅接受白名单字段）。"""
    merged = dict(old)
    for k in ("name", "channel", "target", "secret", "remark"):
        if k in patch:
            merged[k] = str(patch[k] or "")
    for k in ("levels", "rule_ids", "event_types"):
        if k in patch:
            merged[k] = _as_str_list(patch[k])
    if "enabled" in patch:
        merged["enabled"] = bool(patch["enabled"])
    return merged


# ---------------------------------------------------------------------------
# 订阅存储
# ---------------------------------------------------------------------------
class SubscriptionStore:
    def __init__(self, path=None):
        self.path = path or config.SUBSCRIPTIONS_FILE
        self._lock = threading.RLock()
        self._cache = None
        self._cached_mtime = None

    def _read(self):
        """mtime 缓存读取；文件不存在或被改动时重新解析。"""
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except OSError:
                self._cache = []
                self._cached_mtime = None
                return []
            if self._cache is not None and mtime == self._cached_mtime:
                return self._cache
            data = read_json(self.path, {"subscriptions": []})
            self._cache = data.get("subscriptions", [])
            self._cached_mtime = mtime
            return self._cache

    def list(self, owner=None, enabled_only=False):
        items = self._read()
        if owner is not None:
            items = [s for s in items if s.get("owner") == owner]
        if enabled_only:
            items = [s for s in items if s.get("enabled", True)]
        return [dict(s) for s in items]

    def get(self, sub_id):
        for s in self._read():
            if s.get("id") == sub_id:
                return dict(s)
        return None

    def _mutate(self, fn):
        """读-改-写，全程持 storage 锁；写后刷新缓存。"""
        def _do(data):
            data.setdefault("subscriptions", [])
            result = fn(data["subscriptions"])
            return result
        with self._lock:
            result = update_json(self.path, _do, default={"subscriptions": []})
            self._cache = None
            self._cached_mtime = None
            return result

    def create(self, sub, owner):
        now = int(time.time())
        sub.update({
            "id": gen_id("sub_"),
            "owner": owner,
            "enabled": sub.get("enabled", True),
            "created_at": now,
            "updated_at": now,
        })

        def _do(items):
            items.append(sub)
            return sub
        return self._mutate(_do)

    def update(self, sub_id, patch):
        found = {}

        def _do(items):
            for s in items:
                if s.get("id") == sub_id:
                    s.update(merge_subscription(s, patch))
                    s["updated_at"] = int(time.time())
                    found.update(s)
                    return dict(s)
            return None
        result = self._mutate(_do)
        return dict(found) if result else None

    def set_enabled(self, sub_id, enabled):
        return self.update(sub_id, {"enabled": bool(enabled)})

    def delete(self, sub_id):
        def _do(items):
            before = len(items)
            items[:] = [s for s in items if s.get("id") != sub_id]
            return len(items) < before
        return self._mutate(_do)


# ---------------------------------------------------------------------------
# 推送历史存储
# ---------------------------------------------------------------------------
class DeliveryStore:
    def __init__(self, path=None):
        self.path = path or config.DELIVERIES_FILE
        self._lock = threading.RLock()

    def _trim_locked(self, items):
        """按 TTL 与每订阅条数上限裁剪（调用方已持锁）。"""
        from backend.settings_store import get_settings
        ncfg = get_settings().get("notify", {})
        keep = int(ncfg.get("delivery_keep", 1000) or 1000)
        ttl_days = int(ncfg.get("delivery_ttl_days", 30) or 30)
        deadline = time.time() - ttl_days * 86400

        items[:] = [d for d in items if d.get("created_at", 0) >= deadline]
        by_sub = {}
        for d in items:
            by_sub.setdefault(d.get("subscription_id"), []).append(d)
        keep_ids = set()
        for sub_id, group in by_sub.items():
            group.sort(key=lambda d: d.get("created_at", 0), reverse=True)
            for d in group[:keep]:
                keep_ids.add(d.get("id"))
        items[:] = [d for d in items if d.get("id") in keep_ids]
        items.sort(key=lambda d: d.get("created_at", 0), reverse=True)

    def add(self, delivery):
        with self._lock:
            def _do(data):
                items = data.setdefault("deliveries", [])
                items.append(delivery)
                self._trim_locked(items)
                return delivery
            return update_json(self.path, _do, default={"deliveries": []})

    def update(self, delivery_id, **changes):
        with self._lock:
            found = {}

            def _do(data):
                for d in data.setdefault("deliveries", []):
                    if d.get("id") == delivery_id:
                        d.update(changes)
                        found.update(d)
                        return dict(d)
                return None
            result = update_json(self.path, _do, default={"deliveries": []})
            return dict(found) if result else None

    def list(self, subscription_id=None, status=None, limit=100):
        data = read_json(self.path, {"deliveries": []})
        items = data.get("deliveries", [])
        if subscription_id:
            items = [d for d in items if d.get("subscription_id") == subscription_id]
        if status:
            items = [d for d in items if d.get("status") == status]
        items = sorted(items, key=lambda d: d.get("created_at", 0), reverse=True)
        limit = max(1, min(int(limit or 100), 1000))
        return items[:limit]

    def pending(self):
        """进程重启后仍处于 pending 的记录（崩溃时可能正在发送，重启时重试一次）。"""
        return [d for d in self.list(limit=1000) if d.get("status") == "pending"]

    @staticmethod
    def success_rate(items):
        """根据历史记录计算成功率（终态记录口径）。"""
        finished = [d for d in items if d.get("status") in ("success", "failed")]
        if not finished:
            return None
        ok = sum(1 for d in finished if d.get("status") == "success")
        return round(ok / len(finished), 4)
