import os
import sqlite3
from urllib.parse import urlparse

import requests
from flask import (
    Flask, g, redirect, render_template, request, session, url_for, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "dev-secret")

DB_PATH = "app.db"

# ----------------------------
# DB helpers
# ----------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            bio TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 1000
        );

        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account INTEGER NOT NULL,
            to_account INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    db.commit()

def seed_db():
    db = get_db()

    # Seed users (weak auth by design; plaintext passwords)
    users = [
        ("alice", "alice123", 0, "Hi, I'm Alice."),
        ("bob", "bob123", 0, "Bob here."),
        ("admin", "admin123", 1, "Admin account.")
    ]
    for u in users:
        try:
            db.execute(
                "INSERT INTO users (username, password, is_admin, bio) VALUES (?, ?, ?, ?)",
                u
            )
        except sqlite3.IntegrityError:
            pass

    # Seed accounts
    # Two accounts for alice/bob to demonstrate IDOR/logic bugs
    existing = db.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
    if existing == 0:
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("alice", 1500))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("alice", 500))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("bob", 2000))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("admin", 9999))

    # Seed posts
    post_count = db.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
    if post_count == 0:
        db.execute(
            "INSERT INTO posts (title, body, author) VALUES (?, ?, ?)",
            ("Welcome", "This is a tiny demo app for scanner evaluation.", "admin")
        )

    db.commit()

@app.before_request
def _ensure_db():
    init_db()
    seed_db()

# ----------------------------
# Auth helpers
# ----------------------------
def current_user():
    uname = session.get("username")
    if not uname:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()

def login_required():
    if not session.get("username"):
        return redirect(url_for("login", next=request.path))

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    db = get_db()
    posts = db.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    user = current_user()
    return render_template("index.html", posts=posts, user=user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Intentionally weak auth: plaintext compare
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    if not row:
        return render_template("login.html", error="Invalid creds. Try alice/alice123, bob/bob123, admin/admin123")

    session["username"] = row["username"]
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("username"):
        return login_required()

    db = get_db()
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        bio = request.form.get("bio", "")

        # VULN #4 Stored XSS: bio stored unsanitized
        db.execute("UPDATE users SET bio = ? WHERE username = ?", (bio, user["username"]))
        db.commit()
        return redirect(url_for("profile"))

    # Show your accounts
    accounts = db.execute(
        "SELECT * FROM accounts WHERE owner_username = ? ORDER BY id",
        (user["username"],),
    ).fetchall()

    return render_template("profile.html", user=user, accounts=accounts)

@app.route("/api/update", methods=["POST"])
def api_update():
    """
    VULN #2 Hidden parameter privilege escalation.
    If request has is_admin=true, promote current user.
    Frontend never sends this.
    """
    if not session.get("username"):
        abort(401)

    user = current_user()
    if not user:
        abort(401)

    data = request.get_json(silent=True) or {}

    # Hidden parameter - tool should try parameter discovery
    if str(data.get("is_admin", "")).lower() == "true":
        db = get_db()
        db.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (user["username"],))
        db.commit()
        return {"status": "ok", "message": "User promoted (should not happen)."}, 200

    # normal update path (harmless)
    new_bio = data.get("bio")
    if isinstance(new_bio, str):
        db = get_db()
        db.execute("UPDATE users SET bio = ? WHERE username = ?", (new_bio, user["username"]))
        db.commit()

    return {"status": "ok"}, 200

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not session.get("username"):
        return login_required()

    user = current_user()
    if not user:
        abort(401)

    db = get_db()

    if request.method == "POST":
        from_account = request.form.get("from_account", "")
        to_account = request.form.get("to_account", "")
        amount = request.form.get("amount", "0")

        try:
            from_id = int(from_account)
            to_id = int(to_account)
            amt = int(amount)
        except ValueError:
            return render_template("transfer.html", user=user, error="Invalid input."), 400

        if amt <= 0:
            return render_template("transfer.html", user=user, error="Amount must be > 0."), 400

        # VULN #1 Logic flaw / Broken authorization (IDOR):
        # No ownership validation on from_account.
        from_row = db.execute("SELECT * FROM accounts WHERE id = ?", (from_id,)).fetchone()
        to_row = db.execute("SELECT * FROM accounts WHERE id = ?", (to_id,)).fetchone()
        if not from_row or not to_row:
            return render_template("transfer.html", user=user, error="Account not found."), 404

        # Perform transfer without checking from_row.owner_username == current user
        if from_row["balance"] < amt:
            return render_template("transfer.html", user=user, error="Insufficient funds."), 400

        db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amt, from_id))
        db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amt, to_id))
        db.execute(
            "INSERT INTO transfers (from_account, to_account, amount, created_by) VALUES (?, ?, ?, ?)",
            (from_id, to_id, amt, user["username"])
        )
        db.commit()

        return redirect(url_for("profile"))

    # For convenience, show all accounts (this also makes IDOR easy to exploit)
    all_accounts = db.execute(
        "SELECT a.id, a.owner_username, a.balance FROM accounts a ORDER BY a.id"
    ).fetchall()

    return render_template("transfer.html", user=user, all_accounts=all_accounts)

@app.route("/search")
def search():
    """
    VULN #3 SQL injection:
    naive string concatenation in LIKE clause.
    """
    q = request.args.get("q", "")
    db = get_db()

    # Deliberately unsafe
    sql = f"SELECT id, title, body, author, created_at FROM posts WHERE title LIKE '%{q}%' ORDER BY id DESC"
    try:
        rows = db.execute(sql).fetchall()
    except sqlite3.Error as e:
        rows = []
        return render_template("search.html", q=q, posts=rows, error=f"SQL error: {e}")

    return render_template("search.html", q=q, posts=rows)

@app.route("/fetch")
def fetch():
    """
    VULN #5 SSRF:
    Fetches arbitrary URL server-side, returns snippet.
    """
    if not session.get("username"):
        return login_required()

    url = request.args.get("url", "")
    if not url:
        return render_template("index.html", posts=get_db().execute("SELECT * FROM posts ORDER BY id DESC").fetchall(),
                               user=current_user(), error="Provide ?url=https://example.com")

    # Intentionally weak validation: only checks scheme exists
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return render_template("index.html", posts=get_db().execute("SELECT * FROM posts ORDER BY id DESC").fetchall(),
                               user=current_user(), error="Only http/https allowed"), 400

    try:
        r = requests.get(url, timeout=3)
        text = r.text[:2000]
        return {"url": url, "status": r.status_code, "snippet": text}, 200
    except Exception as e:
        return {"url": url, "error": str(e)}, 500

@app.route("/admin")
def admin():
    """
    Admin dashboard that renders user bios unsafely.
    This is where stored XSS pops (second-order-ish).
    """
    if not session.get("username"):
        return login_required()

    user = current_user()
    if not user:
        abort(401)

    # Gate by is_admin flag (which can be set via hidden param vuln)
    if int(user["is_admin"]) != 1:
        abort(403)

    db = get_db()
    users = db.execute("SELECT username, is_admin, bio FROM users ORDER BY username").fetchall()
    transfers = db.execute(
        "SELECT * FROM transfers ORDER BY id DESC LIMIT 25"
    ).fetchall()
    return render_template("admin.html", user=user, users=users, transfers=transfers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
