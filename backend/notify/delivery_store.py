"""通知推送记录存储：按天分片 JSON + 成功率统计。

记录文件：data/notify/deliveries/YYYYMMDD.json，结构 ``{"deliveries": [...]}``。
与告警分片一致，采用内存索引 + 读-改-写原子落盘；启动时加载最近两天记录，
用于历史查询、成功率统计，以及把「仍在重试窗口内的失败记录」恢复到重试队列。

记录状态机：
    pending  →（首次发送）→ success
                          ↘ failed（attempts <= retry_max 时进入 retrying，等待退避重试）
    retrying →（重试发送）→ success / retrying / failed（超过次数后终态 failed）
"""
import os
import threading
import time

from backend import config
from backend.storage import (read_json, atomic_write_json, gen_id)

# 终态与中间态
STATUS_PENDING = "pending"
STATUS_SUCCESS = "success"
STATUS_RETRYING = "retrying"
STATUS_FAILED = "failed"
FINAL_STATUSES = (STATUS_SUCCESS, STATUS_FAILED)


def day_key(ts):
    """本地时区（东八区）的天分片键，如 20260926。"""
    t = time.gmtime(ts - 8 * 3600)
    return f"{t.tm_year:04d}{t.tm_mon:02d}{t.tm_mday:02d}"


def shard_path(ts):
    return os.path.join(config.DELIVERIES_DIR, f"{day_key(ts)}.json")


def channel_target(channel):
    """渠道的人类可读目标（记录里不保存 secret）。"""
    if channel.get("type") == "webhook":
        return channel.get("url", "")
    return channel.get("to", "")


class DeliveryStore:
    def __init__(self, retain_days=7):
        self._records = {}          # id -> record（内存源，仅最近 retain_days 天）
        self._lock = threading.RLock()
        self.retain_days = max(1, retain_days)
        self._load_recent()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load_recent(self):
        now = time.time()
        for back in range(self.retain_days):
            path = shard_path(now - back * 86400)
            data = read_json(path, {"deliveries": []})
            for r in data.get("deliveries", []):
                if r.get("id"):
                    self._records[r["id"]] = r

    def _persist(self, record):
        path = shard_path(record["created_at"])
        with self._lock:
            day = day_key(record["created_at"])
            items = [r for r in self._records.values()
                     if day_key(r.get("created_at", 0)) == day]
        atomic_write_json(path, {"deliveries": items})

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def create(self, sub, channel, alert_snapshot, retry_max):
        now = time.time()
        record = {
            "id": gen_id("dlv_"),
            "sub_id": sub.get("id"),
            "sub_name": sub.get("name", ""),
            "owner": sub.get("owner"),
            "channel_type": channel.get("type"),
            "channel_target": channel_target(channel),
            "alert": alert_snapshot,
            "status": STATUS_PENDING,
            "attempts": 0,
            "max_attempts": 1 + max(0, int(retry_max)),
            "next_retry_at": None,
            "last_error": "",
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self._records[record["id"]] = record
        self._persist(record)
        return record

    def update_result(self, record_id, status, error="", next_retry_at=None):
        with self._lock:
            r = self._records.get(record_id)
            if r is None:
                return None
            r["status"] = status
            r["attempts"] = r.get("attempts", 0) + 1
            r["last_error"] = error or ""
            r["next_retry_at"] = next_retry_at
            r["updated_at"] = time.time()
            snapshot = dict(r)
        self._persist(snapshot)
        return snapshot

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get(self, record_id):
        with self._lock:
            r = self._records.get(record_id)
            return dict(r) if r else None

    def list(self, sub_id=None, owner=None, status=None, page=1, page_size=20):
        with self._lock:
            items = list(self._records.values())
        if sub_id:
            items = [r for r in items if r.get("sub_id") == sub_id]
        if owner is not None:
            items = [r for r in items if r.get("owner") == owner]
        if status:
            items = [r for r in items if r.get("status") == status]
        items.sort(key=lambda r: -r.get("created_at", 0))
        total = len(items)
        page = max(1, page)
        page_size = max(1, page_size)
        start = (page - 1) * page_size
        return total, items[start:start + page_size]

    def stats(self, sub_id=None, owner=None):
        """推送统计：总量、成功/失败终态数、进行中数量与成功率。"""
        with self._lock:
            items = list(self._records.values())
        if sub_id:
            items = [r for r in items if r.get("sub_id") == sub_id]
        if owner is not None:
            items = [r for r in items if r.get("owner") == owner]
        total = len(items)
        success = sum(1 for r in items if r.get("status") == STATUS_SUCCESS)
        failed = sum(1 for r in items if r.get("status") == STATUS_FAILED)
        retrying = sum(1 for r in items if r.get("status") == STATUS_RETRYING)
        pending = sum(1 for r in items if r.get("status") == STATUS_PENDING)
        finished = success + failed
        rate = round(success / finished, 4) if finished else None
        return {
            "total": total,
            "success": success,
            "failed": failed,
            "retrying": retrying,
            "pending": pending,
            "success_rate": rate,
        }

    def recoverable(self):
        """启动恢复：仍有重试机会的失败记录（retrying 且未超最大次数）。"""
        now = time.time()
        out = []
        with self._lock:
            for r in self._records.values():
                if r.get("status") == STATUS_RETRYING and \
                        r.get("attempts", 0) < r.get("max_attempts", 1):
                    # 过期的退避时间直接置为到期
                    nr = r.get("next_retry_at") or now
                    r["next_retry_at"] = min(nr, now)
                    out.append(dict(r))
        return out
