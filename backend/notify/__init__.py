"""告警通知订阅与推送包。

- subscription_store：订阅 CRUD 与匹配过滤（JSON 持久化）
- delivery_store：推送记录（按天分片 JSON）与成功率统计
- notifier：通知调度器，监听引擎新告警 → 匹配订阅 → 后台线程推送 → 有限次重试
"""
