"""系统设置 API。"""
from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import role_required, login_required
from backend.settings_store import get_settings, save_settings

bp = Blueprint("settings", __name__, url_prefix="/api/settings")


@bp.route("", methods=["GET"])
@login_required
def read_settings():
    settings = get_settings()
    for key in ("event_types", "site_name"):
        settings.pop(key, None)
    # SMTP 密码属于敏感信息，回传时脱敏
    smtp = settings.get("notification", {}).get("smtp")
    if smtp and smtp.get("password"):
        smtp["password"] = "******"
    return jsonify({"ok": True, "settings": settings})


@bp.route("", methods=["PUT"])
@role_required("admin", "viewer")
def write_settings():
    patch = request.get_json(force=True, silent=True) or {}
    # 前端密码框留空（或回显的脱敏值）表示保留原密码
    smtp_patch = patch.get("notification", {}).get("smtp")
    if isinstance(smtp_patch, dict):
        pwd = smtp_patch.get("password")
        if not pwd or pwd == "******":
            current = get_settings()
            smtp_patch["password"] = current.get("notification", {}).get("smtp", {}).get("password", "")
    merged = save_settings(patch)
    # 若切换了匹配模式，同步重建引擎网络
    if "engine" in patch and "mode" in patch.get("engine", {}):
        runtime.engine.registry.set_mode(patch["engine"]["mode"])
    # 通知开关可热切换（SMTP 参数发送时实时读取，同样即时生效）
    if runtime.notifier is not None and "notification" in patch:
        enabled = merged.get("notification", {}).get("enabled", True)
        if enabled:
            runtime.notifier.attach(runtime.engine)
        else:
            runtime.notifier.detach()
    return jsonify({"ok": True, "settings": merged})
