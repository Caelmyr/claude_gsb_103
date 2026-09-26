"""端到端冒烟测试：订阅匹配、Webhook 推送、失败重试、历史与成功率。"""
import json
import os
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 隔离数据目录，避免污染开发数据
TEST_DATA = "/tmp/risk_notify_test_data"
shutil.rmtree(TEST_DATA, ignore_errors=True)
os.environ["RISK_SECRET"] = "test"

import backend.config as config
config.DATA_DIR = TEST_DATA
for _n in ("NOTIFY_DIR", "SETTINGS_DIR", "ALERTS_DIR", "EVENTS_DIR", "RULES_DIR",
           "VERSIONS_DIR", "USERS_DIR", "FLOWS_DIR", "DICT_DIR", "WINDOWS_DIR"):
    setattr(config, _n, os.path.join(TEST_DATA, _n.lower()))
config.USERS_FILE = os.path.join(config.USERS_DIR, "users.json")
config.SETTINGS_FILE = os.path.join(config.SETTINGS_DIR, "system.json")
config.DICT_FILE = os.path.join(config.DICT_DIR, "dict.json")
config.SUBSCRIPTIONS_FILE = os.path.join(config.NOTIFY_DIR, "subscriptions.json")
config.DELIVERIES_FILE = os.path.join(config.NOTIFY_DIR, "deliveries.json")

# 加快重试：1s 退避基数
config.DEFAULT_SETTINGS["notify"]["max_retries"] = 3
config.DEFAULT_SETTINGS["notify"]["retry_backoff_base"] = 1
config.DEFAULT_SETTINGS["notify"]["timeout_sec"] = 3

received = []
fail_n = {"n": 0}


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        received.append(json.loads(body.decode("utf-8")))
        if self.path == "/fail" and fail_n["n"] < 2:
            fail_n["n"] += 1
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"boom")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), WebhookHandler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

from backend.app import create_app
app = create_app()
app.config["TESTING"] = True
client = app.test_client()

# 登录 admin
r = client.post("/api/login", json={"username": "admin", "password": "admin123"})
assert r.status_code == 200, r.data

# 1) 新建订阅：高/严重 + webhook
r = client.post("/api/subscriptions", json={
    "name": "高危告警", "channel": "webhook",
    "target": f"http://127.0.0.1:{port}/hook", "levels": ["高", "严重"],
    "secret": "topsecret",
})
assert r.status_code == 200, r.data
sub = r.get_json()["subscription"]
sid = sub["id"]
print("1) 创建订阅 OK:", sid)

# 2) 校验：非法 URL
r = client.post("/api/subscriptions", json={
    "name": "bad", "channel": "webhook", "target": "ftp://x"})
assert r.status_code == 400
# 非法邮箱
r = client.post("/api/subscriptions", json={
    "name": "bad", "channel": "email", "target": "not-an-email"})
assert r.status_code == 400
print("2) 参数校验 OK")

# 3) 触发一条「严重」告警（超大额支付 > 500000）
r = client.post("/api/events/ingest", json={
    "type": "payment", "amount": 999999, "ip": "1.2.3.4", "user_id": "u1"})
assert r.status_code == 200, r.data
time.sleep(1.2)
assert len(received) == 1, f"应收到 1 条 webhook，实际 {len(received)}"
payload = received[0]
assert payload["level"] == "严重", payload
assert payload["rule_id"] == "rule_huge_amount"
print("3) 严重告警即时推送 OK:", payload["title"])

# 4) 「低」等级告警不应推送（新设备登录）
r = client.post("/api/events/ingest", json={
    "type": "login", "ip": "9.9.9.9", "user_id": "u2", "risk_hint": "new_device"})
time.sleep(0.5)
assert len(received) == 1, "低等级告警不应推送"
print("4) 等级过滤 OK（低等级未推送）")

# 5) 停用后不再推送
client.post(f"/api/subscriptions/{sid}/enable", json={"enabled": False})
r = client.post("/api/events/ingest", json={
    "type": "payment", "amount": 888888, "ip": "5.6.7.8", "user_id": "u3"})
time.sleep(0.5)
assert len(received) == 1, "停用后不应推送"
client.post(f"/api/subscriptions/{sid}/enable", json={"enabled": True})
print("5) 启停 OK")

# 6) 规则过滤：仅订阅 rule_sms_bomb（严重）
r = client.post("/api/subscriptions", json={
    "name": "仅短信轰炸", "channel": "webhook",
    "target": f"http://127.0.0.1:{port}/hook",
    "rule_ids": ["rule_sms_bomb"]})
sid2 = r.get_json()["subscription"]["id"]
# 超大额（严重但规则不符）不应推给订阅2
client.post("/api/events/ingest", json={
    "type": "payment", "amount": 777777, "ip": "10.0.0.1", "user_id": "u9"})
time.sleep(0.8)
# 订阅1（高/严重，全规则）应收到；订阅2 不应收到
n_after = len(received)
assert n_after == 2, f"订阅1应收到，订阅2不应收到，实际 {n_after}"

# 触发短信轰炸：同一 ip 60s 内 >20 次 sms
for i in range(21):
    client.post("/api/events/ingest", json={
        "type": "sms", "ip": "6.6.6.6", "user_id": f"sms{i}"})
time.sleep(1.5)
# 两个订阅都应收到该告警
assert len(received) >= 4, f"短信轰炸应同时命中两个订阅，收到 {len(received)}"
assert any(h["rule_id"] == "rule_sms_bomb" for h in received)
print("6) 规则过滤 + 多订阅 fan-out OK")

# 7) 事件类型过滤
r = client.post("/api/subscriptions", json={
    "name": "仅登录类事件", "channel": "webhook",
    "target": f"http://127.0.0.1:{port}/hook",
    "event_types": ["login"], "levels": ["高", "严重"]})
sid3 = r.get_json()["subscription"]["id"]
# 高频登录（同 IP 60s 内 6 次）
for i in range(6):
    client.post("/api/events/ingest", json={
        "type": "login", "ip": "7.7.7.7", "user_id": f"l{i}"})
time.sleep(1.5)
login_pushes = [h for h in received if h["event"].get("type") == "login"]
assert login_pushes, "事件类型订阅应收到登录告警"
print("7) 事件类型过滤 OK")

# 8) 失败重试：前 2 次 500，第 3 次成功
r = client.post("/api/subscriptions", json={
    "name": "会失败的订阅", "channel": "webhook",
    "target": f"http://127.0.0.1:{port}/fail"})
sid4 = r.get_json()["subscription"]["id"]
client.post("/api/events/ingest", json={
    "type": "payment", "amount": 666666, "ip": "8.8.8.8", "user_id": "u8"})
# 等待首次 + 2 次重试（退避 1s, 2s）
deadline = time.time() + 15
statuses = None
while time.time() < deadline:
    r = client.get(f"/api/subscriptions/{sid4}/deliveries")
    dlv = r.get_json()["deliveries"]
    if dlv and dlv[0]["status"] == "success":
        statuses = dlv[0]
        break
    time.sleep(0.5)
assert statuses is not None, "重试后应成功"
assert len(statuses["attempts"]) == 3, f"应尝试 3 次，实际 {statuses['attempts']}"
assert [a.get("http_status") for a in statuses["attempts"]] == [500, 500, 200]
print("8) 失败重试 OK（500,500,200），尝试次数：", len(statuses["attempts"]))

# 9) 彻底失败（持续 500）→ max_retries 耗尽 → failed
fail_n["n"] = 0
# 让 /fail 永远失败：再造一个永久失败端点
class PermanentHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(503)
        self.end_headers()
    def log_message(self, *a): pass
server2 = HTTPServer(("127.0.0.1", 0), PermanentHandler)
port2 = server2.server_address[1]
threading.Thread(target=server2.serve_forever, daemon=True).start()
r = client.post("/api/subscriptions", json={
    "name": "必失败", "channel": "webhook",
    "target": f"http://127.0.0.1:{port2}/x"})
sid5 = r.get_json()["subscription"]["id"]
client.post("/api/events/ingest", json={
    "type": "payment", "amount": 555555, "ip": "4.4.4.4", "user_id": "u5"})
deadline = time.time() + 20
final = None
while time.time() < deadline:
    r = client.get(f"/api/subscriptions/{sid5}/deliveries")
    dlv = r.get_json()["deliveries"]
    if dlv and dlv[0]["status"] in ("success", "failed"):
        final = dlv[0]
        if final["status"] == "failed":
            break
    time.sleep(0.5)
assert final and final["status"] == "failed", f"最终应为 failed：{final and final['status']}"
assert len(final["attempts"]) == 3, f"首次+{3-1}次重试=3 次，实际 {len(final['attempts'])}"
print("9) 重试耗尽标记 failed OK，尝试次数：", len(final["attempts"]))

# 10) 列表带成功率
r = client.get("/api/subscriptions")
slist = {s["id"]: s for s in r.get_json()["subscriptions"]}
stats5 = slist[sid5]["stats"]
assert stats5["failed"] >= 1 and stats5["success_rate"] == 0.0, stats5
stats1 = slist[sid]["stats"]
assert stats1["success"] >= 1 and stats1["success_rate"] == 1.0, stats1
print("10) 推送历史与成功率 OK:", {k: slist[sid5]["stats"][k] for k in
      ("total", "success", "failed", "success_rate")})

# 11) 修改订阅
r = client.put(f"/api/subscriptions/{sid3}", json={"name": "登录告警(改)", "levels": []})
assert r.status_code == 200 and r.get_json()["subscription"]["name"] == "登录告警(改)"
# 删除
r = client.delete(f"/api/subscriptions/{sid3}")
assert r.status_code == 200
assert client.get(f"/api/subscriptions/{sid3}").status_code == 404
print("11) 修改 / 删除 OK")

# 12) 手动测试
r = client.post(f"/api/subscriptions/{sid}/test")
assert r.status_code == 200 and r.get_json()["success"] is True, r.data
print("12) 手动测试推送 OK")

# 13) 权限：分析师 alice 不能动 admin 的订阅
client.post("/api/login", json={"username": "alice", "password": "123456"})
r = client.get(f"/api/subscriptions/{sid}")
assert r.status_code == 403, r.status_code
r = client.get("/api/subscriptions")
assert all(s["owner"] != "admin" for s in r.get_json()["subscriptions"])
print("13) 订阅归属权限隔离 OK")

# 14) SMTP 设置（掩码）
client.post("/api/login", json={"username": "admin", "password": "admin123"})
r = client.put("/api/subscriptions/settings", json={
    "smtp": {"host": "smtp.example.com", "port": 465, "ssl": True,
             "username": "risk@example.com", "password": "secret123",
             "from_addr": "risk@example.com"}})
assert r.status_code == 200, r.data
assert r.get_json()["settings"]["smtp"]["password"] == "********"
r2 = client.put("/api/subscriptions/settings", json={
    "smtp": {"host": "smtp.example.com", "password": "********", "port": 587, "ssl": False}})
# 掩码回传不应覆盖原密码
from backend.settings_store import get_settings
assert get_settings()["notify"]["smtp"]["password"] == "secret123"
assert get_settings()["notify"]["smtp"]["port"] == 587
print("14) SMTP 全局设置与密码掩码 OK")

server.shutdown()
print("\n全部测试通过 ✅")
