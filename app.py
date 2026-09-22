import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db
import pfsense
from mail import send_invite_email

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]  # required: fail fast if not set

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
INVITE_TTL = timedelta(hours=24)


def parse_descr(descr):
    """Reverse of the "{ID} - {Họ tên}" format written by add_ip."""
    if " - " in descr:
        employee_id, full_name = descr.split(" - ", 1)
        return employee_id, full_name
    return "", descr


ACTION_META = {
    "add_static_ip": ("Tạo mới", "pill-create"),
    "update_static_ip": ("Cập nhật", "pill-update"),
    "revoke_static_ip": ("Thu hồi", "pill-revoke"),
    "invite_user": ("Mời user", "pill-update"),
    "reset_password": ("Reset mật khẩu", "pill-update"),
    "delete_user": ("Xoá user", "pill-revoke"),
    "account_created": ("Tạo tài khoản", "pill-create"),
}


# ---------- bootstrap ----------

def seed_admin():
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not email or not password:
        return
    with closing(db.get_db()) as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        if exists:
            return
        try:
            conn.execute(
                "INSERT INTO users (email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                (email, generate_password_hash(password), os.environ.get("ADMIN_NAME", "Admin"), db.now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # another worker process seeded it first


db.init_db()
seed_admin()


# ---------- auth helpers ----------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["action_meta"] = lambda action: ACTION_META.get(action, (action, "pill-update"))


def check_csrf():
    if request.form.get("_csrf") != session.get("_csrf"):
        abort(400, "invalid csrf token")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        with closing(db.get_db()) as conn:
            g.user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not g.user:
            session.clear()


@app.context_processor
def inject_user():
    return {"current_user": g.user}


# ---------- login / logout ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with closing(db.get_db()) as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Sai email hoặc mật khẩu.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- dashboard ----------

@app.route("/")
@login_required
def dashboard():
    try:
        usage = pfsense.usage_summary()
        error = None
    except pfsense.PfSenseError as exc:
        usage, error = {}, str(exc)

    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds")
    with closing(db.get_db()) as conn:
        recent = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 10").fetchall()
        week_stats = conn.execute(
            "SELECT "
            " SUM(action = 'add_static_ip') AS added,"
            " SUM(action = 'revoke_static_ip') AS revoked,"
            " SUM(action = 'account_created') AS accounts "
            "FROM audit_log WHERE ts >= ?",
            (week_ago,),
        ).fetchone()
    return render_template("dashboard.html", usage=usage, error=error, recent=recent, week_stats=week_stats)


# ---------- add static IP ----------

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_ip():
    if request.method == "POST":
        check_csrf()
        range_key = request.form.get("range_key")
        mac = request.form.get("mac", "").strip().lower()
        employee_id = request.form.get("employee_id", "").strip()
        full_name = request.form.get("full_name", "").strip()

        if range_key not in pfsense.RANGES:
            flash("Range IP không hợp lệ.", "error")
        elif not MAC_RE.match(mac):
            flash("MAC address không hợp lệ (định dạng xx:xx:xx:xx:xx:xx).", "error")
        elif not full_name:
            flash("Họ tên nhân viên là bắt buộc.", "error")
        else:
            try:
                ip = pfsense.next_free_ip(range_key)
                if not ip:
                    flash(
                        f"Hết IP trống trong range {pfsense.RANGE_LABELS[range_key]}. "
                        "Vui lòng xoá bớt IP của nhân viên đã nghỉ việc hoặc liên hệ IT để mở thêm range IP.",
                        "error",
                    )
                else:
                    descr = f"{employee_id} - {full_name}" if employee_id else full_name
                    pfsense.add_static_mapping(mac, ip, descr)
                    db.log_action(
                        g.user["email"], "add_static_ip",
                        f"Cấp {ip} cho {descr} ({pfsense.RANGE_LABELS[range_key]})",
                    )
                    flash(f"Đã tạo static IP {ip} cho {full_name}.", "success")
                    return redirect(url_for("add_ip"))
            except pfsense.PfSenseError as exc:
                flash(f"Lỗi pfSense: {exc}", "error")

    try:
        usage = pfsense.usage_summary()
    except pfsense.PfSenseError:
        usage = {}
    return render_template("add.html", ranges=pfsense.RANGE_LABELS, usage=usage)


@app.route("/add/next-ip")
@login_required
def next_ip_preview():
    range_key = request.args.get("range_key")
    exclude = [ip for ip in request.args.get("exclude", "").split(",") if ip]
    if range_key not in pfsense.RANGES:
        return {"ip": None}
    try:
        return {"ip": pfsense.next_free_ip(range_key, exclude=exclude)}
    except pfsense.PfSenseError as exc:
        return {"ip": None, "error": str(exc)}


# ---------- revoke static IP ----------

@app.route("/revoke", methods=["GET", "POST"])
@login_required
def revoke_ip():
    if request.method == "POST":
        check_csrf()
        ids = [int(i) for i in request.form.getlist("mapping_id")]
        if not ids:
            flash("Chưa chọn IP nào để thu hồi.", "error")
        else:
            try:
                mappings = {m["id"]: m for m in pfsense.list_static_mappings()}
                details = [
                    f"Thu hồi {mappings[i]['ipaddr']} — {mappings[i].get('descr') or mappings[i]['mac']}"
                    for i in ids if i in mappings
                ]
                pfsense.delete_static_mappings(ids)
                for line in details:
                    db.log_action(g.user["email"], "revoke_static_ip", line)
                flash(f"Đã thu hồi {len(details)} static IP.", "success")
            except pfsense.PfSenseError as exc:
                flash(f"Lỗi pfSense: {exc}", "error")
        return redirect(url_for("revoke_ip", q=request.args.get("q", "")))

    query = request.args.get("q", "").strip().lower()
    try:
        mappings = pfsense.list_static_mappings()
        error = None
    except pfsense.PfSenseError as exc:
        mappings, error = [], str(exc)

    rows = []
    for m in mappings:
        descr = m.get("descr") or ""
        employee_id, full_name = parse_descr(descr)
        rows.append({
            "id": m["id"],
            "ip": m["ipaddr"],
            "mac": m["mac"],
            "descr": descr,
            "employee_id": employee_id,
            "full_name": full_name,
            "range_label": pfsense.RANGE_LABELS.get(pfsense.range_of(m["ipaddr"]), "?"),
        })
    if query:
        rows = [
            r for r in rows
            if query in r["ip"].lower() or query in r["mac"].lower() or query in r["descr"].lower()
        ]
    if rows:
        online = pfsense.online_status_map()
        for r in rows:
            r["online"] = online.get(r["ip"], False)
    return render_template("revoke.html", rows=rows, query=request.args.get("q", ""), error=error)


@app.route("/revoke/update/<int:mapping_id>", methods=["POST"])
@login_required
def update_ip(mapping_id):
    check_csrf()
    mac = request.form.get("mac", "").strip().lower()
    employee_id = request.form.get("employee_id", "").strip()
    full_name = request.form.get("full_name", "").strip()
    q = request.form.get("q", "")

    if not MAC_RE.match(mac):
        flash("MAC address không hợp lệ (định dạng xx:xx:xx:xx:xx:xx).", "error")
    elif not full_name:
        flash("Họ tên nhân viên là bắt buộc.", "error")
    else:
        try:
            descr = f"{employee_id} - {full_name}" if employee_id else full_name
            updated = pfsense.update_static_mapping(mapping_id, mac, descr)
            db.log_action(g.user["email"], "update_static_ip", f"Cập nhật {updated['ipaddr']}: {descr} · MAC {mac}")
            flash("Đã cập nhật static IP.", "success")
        except pfsense.PfSenseError as exc:
            flash(f"Lỗi pfSense: {exc}", "error")
    return redirect(url_for("revoke_ip", q=q))


# ---------- account ----------

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action")
        with closing(db.get_db()) as conn:
            if action == "update_profile":
                full_name = request.form.get("full_name", "").strip()
                if full_name:
                    conn.execute("UPDATE users SET full_name = ? WHERE id = ?", (full_name, g.user["id"]))
                    conn.commit()
                    flash("Đã cập nhật thông tin.", "success")
            elif action == "change_password":
                current = request.form.get("current_password", "")
                new = request.form.get("new_password", "")
                if not check_password_hash(g.user["password_hash"], current):
                    flash("Mật khẩu hiện tại không đúng.", "error")
                elif len(new) < 8:
                    flash("Mật khẩu mới cần tối thiểu 8 ký tự.", "error")
                else:
                    conn.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?",
                        (generate_password_hash(new), g.user["id"]),
                    )
                    conn.commit()
                    flash("Đã đổi mật khẩu.", "success")
        return redirect(url_for("account"))

    users, invites = [], []
    if g.user["role"] == "admin":
        with closing(db.get_db()) as conn:
            users = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
            invites = conn.execute(
                "SELECT * FROM invites WHERE used = 0 AND expires_at > ? ORDER BY created_at",
                (db.now_iso(),),
            ).fetchall()
    return render_template("account.html", users=users, invites=invites)


@app.route("/account/invite", methods=["POST"])
@login_required
@admin_required
def invite_user():
    check_csrf()
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Cần nhập email.", "error")
        return redirect(url_for("account"))

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with closing(db.get_db()) as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            flash("Email đã có tài khoản.", "error")
            return redirect(url_for("account"))
        conn.execute(
            "INSERT INTO invites (token, email, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
            (token, email, db.now_iso(), (now + INVITE_TTL).isoformat(timespec="seconds")),
        )
        conn.commit()

    link = url_for("accept_invite", token=token, _external=True)
    sent = send_invite_email(email, link)
    db.log_action(g.user["email"], "invite_user", f"Mời {email} tham gia làm operator")
    if sent:
        flash(f"Đã gửi lời mời tới {email}.", "success")
    else:
        flash(f"SMTP chưa cấu hình. Gửi link này cho {email}: {link}", "success")
    return redirect(url_for("account"))


@app.route("/account/invite/<token>/cancel", methods=["POST"])
@login_required
@admin_required
def cancel_invite(token):
    check_csrf()
    with closing(db.get_db()) as conn:
        invite = conn.execute("SELECT * FROM invites WHERE token = ?", (token,)).fetchone()
        if invite:
            conn.execute("DELETE FROM invites WHERE token = ?", (token,))
            conn.commit()
            db.log_action(g.user["email"], "invite_user", f"Huỷ lời mời tới {invite['email']}")
    flash("Đã huỷ lời mời.", "success")
    return redirect(url_for("account"))


@app.route("/accept-invite/<token>", methods=["GET", "POST"])
def accept_invite(token):
    with closing(db.get_db()) as conn:
        invite = conn.execute("SELECT * FROM invites WHERE token = ?", (token,)).fetchone()
    if not invite or invite["used"] or invite["expires_at"] < datetime.now(timezone.utc).isoformat(timespec="seconds"):
        abort(404)

    if request.method == "POST":
        check_csrf()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        if not full_name or len(password) < 8:
            flash("Cần nhập họ tên và mật khẩu tối thiểu 8 ký tự.", "error")
        else:
            with closing(db.get_db()) as conn:
                conn.execute(
                    "INSERT INTO users (email, password_hash, full_name, role, created_at) "
                    "VALUES (?, ?, ?, 'operator', ?)",
                    (invite["email"], generate_password_hash(password), full_name, db.now_iso()),
                )
                conn.execute("UPDATE invites SET used = 1 WHERE token = ?", (token,))
                conn.commit()
            db.log_action(invite["email"], "account_created", f"Tạo tài khoản qua lời mời ({invite['email']})")
            flash("Tạo tài khoản thành công, mời đăng nhập.", "success")
            return redirect(url_for("login"))

    return render_template("accept_invite.html", email=invite["email"], token=token)


@app.route("/account/reset-password/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def reset_password(user_id):
    check_csrf()
    new_password = secrets.token_urlsafe(9)
    with closing(db.get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["role"] == "admin":
            abort(404)
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        conn.commit()
    db.log_action(g.user["email"], "reset_password", f"Reset mật khẩu cho {user['email']}")
    flash(f"Mật khẩu mới cho {user['email']}: {new_password}", "success")
    return redirect(url_for("account"))


@app.route("/account/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    check_csrf()
    with closing(db.get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["role"] == "admin":
            abort(404)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    db.log_action(g.user["email"], "delete_user", f"Xoá tài khoản {user['email']}")
    flash(f"Đã xoá tài khoản {user['email']}.", "success")
    return redirect(url_for("account"))


# ---------- log ----------

@app.route("/logs")
@login_required
def logs():
    query = request.args.get("q", "").strip().lower()
    action_filter = request.args.get("action", "")
    sql = "SELECT * FROM audit_log"
    clauses, params = [], []
    if query:
        clauses.append("(LOWER(actor) LIKE ? OR LOWER(details) LIKE ?)")
        params += [f"%{query}%", f"%{query}%"]
    if action_filter:
        clauses.append("action = ?")
        params.append(action_filter)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT 500"
    with closing(db.get_db()) as conn:
        rows = conn.execute(sql, params).fetchall()
        actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    return render_template("logs.html", rows=rows, query=request.args.get("q", ""),
                            action_filter=action_filter, actions=actions)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=bool(os.environ.get("DEBUG")))
