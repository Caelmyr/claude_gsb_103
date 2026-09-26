"""告警通知订阅与推送记录 API。

订阅是属主资源：管理员（admin）与分析师（analyst）可新增/修改/启停/删除；
只读用户（viewer）仅可查看自己的订阅与推送历史。管理员可通过 scope/all 参数
查看并管理全系统的订阅。
"""
from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, current_user
from backend.notify.subscription_store import SubscriptionError

bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")


def _is_admin(user):
    return user.get("role") == "admin"


def _can_manage(user):
    return user.get("role") in ("admin", "analyst")


def _public_sub(sub, viewer):
    """对外的订阅结构：非属主且非管理员时不回传 webhook secret。"""
    out = dict(sub)
    if out.get("owner") != viewer.get("username") and not _is_admin(viewer):
        out["channels"] = [dict(ch, secret="******") if ch.get("secret") else dict(ch)
                           for ch in out.get("channels", [])]
    return out


# ---------------------------------------------------------------------------
# 订阅管理
# ---------------------------------------------------------------------------
@bp.route("/subscriptions", methods=["GET"])
@login_required
def list_subscriptions():
    user = current_user()
    scope_all = request.args.get("scope") == "all" or request.args.get("all") == "1"
    only_mine = request.args.get("mine") == "1"
    notifier = runtime.notifier
    if scope_all and _is_admin(user) and not only_mine:
        subs = notifier.store.list()
    else:
        subs = notifier.store.list(owner=user["username"])

    stats_by_sub = {}
    for s in subs:
        sid = s.get("id")
        owner = s.get("owner") if (scope_all and _is_admin(user) and not only_mine) else user["username"]
        stats_by_sub[sid] = notifier.deliveries.stats(sub_id=sid, owner=owner)

    out = []
    for s in subs:
        item = _public_sub(s, user)
        item["stats"] = stats_by_sub.get(s.get("id"), {})
        out.append(item)
    return jsonify({"ok": True, "subscriptions": out})


@bp.route("/subscriptions", methods=["POST"])
@login_required
def create_subscription():
    user = current_user()
    if not _can_manage(user):
        return jsonify({"ok": False, "error": "只读用户无权创建订阅"}), 403
    body = request.get_json(force=True, silent=True) or {}
    try:
        sub = runtime.notifier.store.create(body, owner=user["username"])
    except SubscriptionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "subscription": sub}), 201


@bp.route("/subscriptions/<sub_id>", methods=["PUT"])
@login_required
def update_subscription(sub_id):
    user = current_user()
    if not _can_manage(user):
        return jsonify({"ok": False, "error": "只读用户无权修改订阅"}), 403
    body = request.get_json(force=True, silent=True) or {}
    try:
        sub = runtime.notifier.store.update(
            sub_id, body, owner=user["username"], is_admin=_is_admin(user))
    except SubscriptionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except PermissionError:
        return jsonify({"ok": False, "error": "无权修改他人的订阅"}), 403
    if sub is None:
        return jsonify({"ok": False, "error": "订阅不存在"}), 404
    return jsonify({"ok": True, "subscription": sub})


@bp.route("/subscriptions/<sub_id>/enable", methods=["POST"])
@login_required
def enable_subscription(sub_id):
    user = current_user()
    if not _can_manage(user):
        return jsonify({"ok": False, "error": "只读用户无权操作订阅"}), 403
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled", True))
    try:
        sub = runtime.notifier.store.set_enabled(
            sub_id, enabled, owner=user["username"], is_admin=_is_admin(user))
    except PermissionError:
        return jsonify({"ok": False, "error": "无权操作他人的订阅"}), 403
    if sub is None:
        return jsonify({"ok": False, "error": "订阅不存在"}), 404
    return jsonify({"ok": True, "subscription": sub})


@bp.route("/subscriptions/<sub_id>", methods=["DELETE"])
@login_required
def delete_subscription(sub_id):
    user = current_user()
    if not _can_manage(user):
        return jsonify({"ok": False, "error": "只读用户无权删除订阅"}), 403
    ok = runtime.notifier.store.delete(
        sub_id, owner=user["username"], is_admin=_is_admin(user))
    if not ok:
        return jsonify({"ok": False, "error": "订阅不存在或无权删除"}), 404
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# 推送历史 / 成功率
# ---------------------------------------------------------------------------
def _history_scope(user, sub_id):
    """确定推送记录查询的属主范围，返回 (owner, error_response)。"""
    if sub_id:
        sub = runtime.notifier.store.get(sub_id)
        if sub is None:
            return None, (jsonify({"ok": False, "error": "订阅不存在"}), 404)
        if sub.get("owner") != user["username"] and not _is_admin(user):
            return None, (jsonify({"ok": False, "error": "无权查看该订阅的推送历史"}), 403)
        return None, None
    return None if _is_admin(user) else user["username"], None


@bp.route("/deliveries", methods=["GET"])
@login_required
def list_deliveries():
    user = current_user()
    sub_id = request.args.get("sub_id")
    owner_q = request.args.get("owner")
    owner, err = _history_scope(user, sub_id)
    if err:
        return err
    if _is_admin(user) and owner_q and not sub_id:
        owner = owner_q
    status = request.args.get("status")
    page = max(1, request.args.get("page", default=1, type=int))
    page_size = min(200, max(1, request.args.get("page_size", default=20, type=int)))
    total, items = runtime.notifier.deliveries.list(
        sub_id=sub_id, owner=owner, status=status, page=page, page_size=page_size)
    return jsonify({"ok": True, "total": total, "deliveries": items,
                    "page": page, "page_size": page_size})


@bp.route("/stats", methods=["GET"])
@login_required
def delivery_stats():
    user = current_user()
    sub_id = request.args.get("sub_id")
    owner, err = _history_scope(user, sub_id)
    if err:
        return err
    stats = runtime.notifier.deliveries.stats(sub_id=sub_id, owner=owner)
    return jsonify({"ok": True, "stats": stats})


# ---------------------------------------------------------------------------
# 渠道连通性测试
# ---------------------------------------------------------------------------
@bp.route("/test", methods=["POST"])
@login_required
def test_channel():
    user = current_user()
    if not _can_manage(user):
        return jsonify({"ok": False, "error": "只读用户无权测试推送渠道"}), 403
    body = request.get_json(force=True, silent=True) or {}
    channel = body.get("channel")
    if not isinstance(channel, dict):
        return jsonify({"ok": False, "error": "缺少 channel 配置"}), 400
    from backend.notify.subscription_store import validate_channels
    try:
        channels = validate_channels([channel])
    except SubscriptionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    ok, error = runtime.notifier.test_channel(channels[0])
    return jsonify({"ok": ok, "message": "测试通知发送成功" if ok else error})
