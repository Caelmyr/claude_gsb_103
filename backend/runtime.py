"""运行时单例：引擎、决策流存储与通知服务的全局引用。

app.py 在启动时调用 init() 注入；各 API 蓝图通过 runtime.engine /
runtime.flow_store / runtime.notifier 访问，避免循环导入。
"""
engine = None
flow_store = None
notifier = None


def init(eng, flows, notifier_service=None):
    global engine, flow_store, notifier
    engine = eng
    flow_store = flows
    notifier = notifier_service
