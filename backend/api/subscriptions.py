"""告警通知订阅 API。

- 订阅 CRUD：GET/POST /api/subscriptions、GET/PUT/DELETE /api/subscriptions/<id>
- 启停：POST /api/subscriptions/<id>/enable
- 推送历史：GET /api/subscriptions/<id>/deliveries、GET /api/subscriptions/deliveries
- 手动测试：POST /api/subscriptions/<id>/test
- 全局通知设置（SMTP/重试参数）：GET/PUT /api/subscriptions/settings

权限：读接口登录即可；写接口需 admin/analyst（与系统中其他写接口保持一致）。
分析师仅能管理自己的订阅，管理员可管理全部。
"""
import copy
from functools import wraps

from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, role_required, current_user
from backend.settings_store import get_settings, save_settings
from backend.notify.store import validate_subscription, merge_subscription

bp = Blueprint("subscriptions", __name__, url_prefix="/api/subscriptions")


def _public_sub(sub):
    out = copy.deepcopy(sub)
    if out.get("secret"):
        out["secret"] = "********"
    out["has_secret"] = bool(sub.get("secret"))
    return out


def _is_admin(user):
    return user.get("role") == "admin"


def manager_required(fn):
    """订阅管理仅允许实际 admin / analyst（viewer 只读）。

    系统内置的 role_required 对角色做了反转映射，无法表达「admin+analyst、
    排除 viewer」的组合，因此这里按真实角色显式校验。
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"ok": False, "error": "未登录或登录已失效"}), 401
        if user.get("role") not in ("admin", "analyst"):
            return jsonify({"ok": False, "error": "权限不足：仅管理员/分析师可管理订阅"}), 403
        return fn(*args, **kwargs)
    return wrapper


def _owned_or_403(sub, user):
    if sub is None:
        return jsonify({"ok": False, "error": "订阅不存在"}), 404
    if not _is_admin(user) and sub.get("owner") != user["username"]:
        return jsonify({"ok": False, "error": "只能操作自己的订阅"}), 403
    return None


@bp.route("", methods=["GET"])
@login_required
def list_subscriptions():
    user = current_user()
    all_subs = runtime.notifier.subscriptions.list()
    # 非管理员只看自己的订阅
    if not _is_admin(user):
        all_subs = [s for s in all_subs if s.get("owner") == user["username"]]

    history = runtime.notifier.deliveries.list(limit=1000)
    rate_map = {}
    for s in all_subs:
        items = [d for d in history if d.get("subscription_id") == s.get("id")]
        rate_map[s["id"]] = {
            "total": len(items),
            "success": sum(1 for d in items if d.get("status") == "success"),
            "failed": sum(1 for d in items if d.get("status") == "failed"),
            "pending": sum(1 for d in items if d.get("status") == "pending"),
            "success_rate": runtime.notifier.deliveries.success_rate(items),
            "last_push": max((d.get("created_at", 0) for d in items), default=0),
        }

    result = []
    for s in all_subs:
        pub = _public_sub(s)
        pub["stats"] = rate_map.get(s["id"], {})
        result.append(pub)
    result.sort(key=lambda s: s.get("created_at", 0), reverse=True)
    return jsonify({"ok": True, "subscriptions": result})


@bp.route("/<sub_id>", methods=["GET"])
@login_required
def get_subscription(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    return jsonify({"ok": True, "subscription": _public_sub(sub)})


@bp.route("", methods=["POST"])
@manager_required
def create_subscription():
    user = current_user()
    body = request.get_json(force=True, silent=True) or {}
    sub, error = validate_subscription(body)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    saved = runtime.notifier.subscriptions.create(sub, owner=user["username"])
    return jsonify({"ok": True, "subscription": _public_sub(saved)})


@bp.route("/<sub_id>", methods=["PUT"])
@manager_required
def update_subscription(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}

    # 合并后整体校验，保证修改后仍然合法
    merged_patch = merge_subscription(sub, body)
    if "secret" in body and str(body.get("secret", "")) == "":
        # 前端提交空 secret 表示「不修改」
        merged_patch["secret"] = sub.get("secret", "")
        body = {k: v for k, v in body.items() if k != "secret"}
    _, error = validate_subscription(merged_patch)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    updated = runtime.notifier.subscriptions.update(sub_id, body)
    return jsonify({"ok": True, "subscription": _public_sub(updated)})


@bp.route("/<sub_id>/enable", methods=["POST"])
@manager_required
def enable_subscription(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", True))
    updated = runtime.notifier.subscriptions.set_enabled(sub_id, enabled)
    return jsonify({"ok": True, "subscription": _public_sub(updated)})


@bp.route("/<sub_id>", methods=["DELETE"])
@manager_required
def delete_subscription(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    runtime.notifier.subscriptions.delete(sub_id)
    return jsonify({"ok": True})


@bp.route("/<sub_id>/test", methods=["POST"])
@manager_required
def test_subscription(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    ok, error, attempt = runtime.notifier.test_subscription(sub)
    return jsonify({"ok": True, "success": ok, "error": error, "attempt": attempt})


# ---------------------------------------------------------------------------
# 推送历史
# ---------------------------------------------------------------------------
@bp.route("/deliveries", methods=["GET"])
@login_required
def all_deliveries():
    user = current_user()
    status = request.args.get("status")
    limit = request.args.get("limit", 100)
    items = runtime.notifier.deliveries.list(status=status, limit=limit)
    if not _is_admin(user):
        items = [d for d in items if d.get("owner") == user["username"]]
    for d in items:
        d.pop("request_payload", None)
    return jsonify({"ok": True, "deliveries": items, "total": len(items)})


@bp.route("/<sub_id>/deliveries", methods=["GET"])
@login_required
def subscription_deliveries(sub_id):
    user = current_user()
    sub = runtime.notifier.subscriptions.get(sub_id)
    err = _owned_or_403(sub, user)
    if err:
        return err
    limit = request.args.get("limit", 50)
    items = runtime.notifier.deliveries.list(subscription_id=sub_id, limit=limit)
    rate = runtime.notifier.deliveries.success_rate(items)
    return jsonify({"ok": True, "deliveries": items, "total": len(items),
                    "success_rate": rate})


# ---------------------------------------------------------------------------
# 全局通知设置（SMTP / 重试参数，仅管理员）
# 注意：本系统 role_required 对角色做了反转映射，实际 admin 解析为 "viewer"，
# 因此限制「仅实际管理员」需写 @role_required("viewer")（与 users 模块约定一致）。
@bp.route("/settings", methods=["GET"])
@login_required
def notify_settings():
    user = current_user()
    cfg = get_settings().get("notify", {})
    out = copy.deepcopy(cfg)
    smtp = out.get("smtp", {})
    if smtp.get("password"):
        smtp["password"] = "********"
    smtp["has_password"] = bool(cfg.get("smtp", {}).get("password"))
    if not _is_admin(user):
        # 分析师只需要知道邮件渠道是否可用，不暴露服务器细节
        out["smtp"] = {"configured": bool(cfg.get("smtp", {}).get("host"))}
    return jsonify({"ok": True, "settings": out})


@bp.route("/settings", methods=["PUT"])
@role_required("viewer")  # 反转映射后 = 仅实际 admin
def update_notify_settings():
    body = request.get_json(force=True, silent=True) or {}
    current = get_settings().get("notify", {})
    patch = {}

    for key in ("max_retries", "timeout_sec", "retry_backoff_base",
                "delivery_keep", "delivery_ttl_days"):
        if key in body:
            try:
                val = int(body[key])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": f"{key} 必须是整数"}), 400
            if val < 0:
                return jsonify({"ok": False, "error": f"{key} 不能为负数"}), 400
            patch[key] = val
    if "max_retries" in patch:
        patch["max_retries"] = min(patch["max_retries"], 10)

    smtp_patch = body.get("smtp")
    if isinstance(smtp_patch, dict):
        smtp = copy.deepcopy(current.get("smtp", {}))
        for key in ("host", "username", "from_addr"):
            if key in smtp_patch:
                smtp[key] = str(smtp_patch[key] or "").strip()
        if "port" in smtp_patch:
            try:
                smtp["port"] = int(smtp_patch["port"])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "SMTP 端口必须是整数"}), 400
        if "ssl" in smtp_patch:
            smtp["ssl"] = bool(smtp_patch["ssl"])
        # 掩码回传表示不修改密码；空串表示清空
        if "password" in smtp_patch and smtp_patch["password"] != "********":
            smtp["password"] = str(smtp_patch["password"] or "")
        patch["smtp"] = smtp

    if not patch:
        return jsonify({"ok": False, "error": "没有可更新的设置项"}), 400
    merged = save_settings({"notify": patch})
    runtime.notifier.settings = merged
    out = copy.deepcopy(merged.get("notify", {}))
    if out.get("smtp", {}).get("password"):
        out["smtp"]["password"] = "********"
        out["smtp"]["has_password"] = True
    return jsonify({"ok": True, "settings": out})
