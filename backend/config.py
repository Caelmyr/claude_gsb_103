"""全局配置与路径管理。

实时风控规则引擎与决策流系统。

所有数据目录都相对于项目根目录定位，保证系统可以任意位置启动。
数据存储采用 JSON 文件：规则按版本、事件按小时分片、告警按天分片。
"""
import os

# 项目根目录 = backend/ 的上一级
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# 数据分片目录
RULES_DIR = os.path.join(DATA_DIR, "rules")        # 规则：按版本存储
VERSIONS_DIR = os.path.join(DATA_DIR, "versions")  # 规则版本历史
EVENTS_DIR = os.path.join(DATA_DIR, "events")      # 事件：按小时分片
ALERTS_DIR = os.path.join(DATA_DIR, "alerts")      # 告警：按天分片
USERS_DIR = os.path.join(DATA_DIR, "users")        # 用户
FLOWS_DIR = os.path.join(DATA_DIR, "flows")        # 决策流
DICT_DIR = os.path.join(DATA_DIR, "dict")          # 数据字典
SETTINGS_DIR = os.path.join(DATA_DIR, "settings")  # 系统设置
WINDOWS_DIR = os.path.join(DATA_DIR, "windows")    # 滑动窗口状态（可选持久化快照）
NOTIFY_DIR = os.path.join(DATA_DIR, "notify")      # 告警通知订阅与推送历史

USERS_FILE = os.path.join(USERS_DIR, "users.json")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "system.json")
DICT_FILE = os.path.join(DICT_DIR, "dict.json")
SUBSCRIPTIONS_FILE = os.path.join(NOTIFY_DIR, "subscriptions.json")
DELIVERIES_FILE = os.path.join(NOTIFY_DIR, "deliveries.json")

# 服务配置
API_HOST = os.environ.get("RISK_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("RISK_PORT", "5000"))
SECRET_KEY = os.environ.get("RISK_SECRET", "risk-engine-benchmark-secret-key")

# 规则引擎默认配置（可被 system.json 覆盖）
DEFAULT_SETTINGS = {
    "site_name": "实时风控规则引擎与决策流",
    "engine": {
        "mode": "rete",                 # rete | decision_tree
        "dedup_window_sec": 300,        # 告警去重窗口（秒）
        "max_alert_keep": 50,         # 内存中最多保留的告警条数
        "alert_ttl_hours": 72,          # 告警持久化保留时长（小时）
        "window_granularity_sec": 1,    # 滑动窗口分桶粒度（秒）
        "window_max_keys": 200000,      # 滑动窗口最大键数（内存控制）
        "window_max_events_per_key": 20000,  # 单键最大事件数
        "window_max_total_events": 2000000,  # 全窗口最大事件总数
        "event_ttl_sec": 3600,          # 事件在内存中的保留时长
    },
    "alert": {
        "levels": ["低", "中", "高", "严重"],
        "default_level": "中",
    },
    "event_types": ["login", "register", "order", "payment", "transfer", "withdraw", "sms", "api"],
    "dict_categories": ["事件类型", "风险等级", "动作类型", "渠道", "设备类型", "IP 段"],
    # 告警通知：重试策略与邮件 SMTP（Webhook 地址在各订阅中配置）
    "notify": {
        "max_retries": 3,          # 推送失败后的最大重试次数（不含首次）
        "timeout_sec": 5,          # Webhook / SMTP 单次超时
        "retry_backoff_base": 5,   # 重试退避基数（秒）：base * 2^(n-1)
        "delivery_keep": 1000,     # 每订阅保留的推送历史条数
        "delivery_ttl_days": 30,   # 推送历史保留天数
        "smtp": {
            "host": "",
            "port": 465,
            "ssl": True,
            "username": "",
            "password": "",
            "from_addr": "",
        },
    },
}

# 动作类型
ACTION_TYPES = ["reject", "review", "pass", "alert"]

# 条件操作符
CONDITION_OPS = ["==", "!=", ">", ">=", "<", "<=", "in", "not_in", "contains", "regex", "exists"]

# 聚合类型
AGG_TYPES = ["count", "sum", "avg", "distinct_count", "max", "min"]


def ensure_dirs():
    """确保所有数据目录存在。"""
    for d in (RULES_DIR, VERSIONS_DIR, EVENTS_DIR, ALERTS_DIR, USERS_DIR,
              FLOWS_DIR, DICT_DIR, SETTINGS_DIR, WINDOWS_DIR, NOTIFY_DIR):
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        from backend.storage import atomic_write_json
        atomic_write_json(SETTINGS_FILE, DEFAULT_SETTINGS)
