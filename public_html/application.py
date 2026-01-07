import os
import sqlite3
from urllib.parse import urlparse

import requests
from flask import (
    Flask, g, redirect, render_template, request, session, url_for, abort
)

# ----------------------------
# App setup
# ----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "dev-secret")

# IMPORTANT: absolute DB path for shared hosting
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

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

    count = db.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
    if count == 0:
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("alice", 1500))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("alice", 500))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("bob", 2000))
        db.execute("INSERT INTO accounts (owner_username, balance) VALUES (?, ?)", ("admin", 9999))

    post_count = db.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
    if post_count == 0:
        db.execute(
            "INSERT INTO posts (title, body, author) VALUES (?, ?, ?)",
            ("Welcome", "This is a deliberately vulnerable demo app.", "admin")
        )

    db.commit()

@app.before_request
def ensure_db():
    init_db()
    seed_db()

# ----------------------------
# Auth helpers
# ----------------------------
def current_user():
    username = session.get("username")
    if not username:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

def login_required():
    return redirect(url_for("login"))

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    posts = get_db().execute(
        "SELECT * FROM posts ORDER BY id DESC"
    ).fetchall()
    return render_template("index.html", posts=posts, user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    user = get_db().execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()

    if not user:
        return render_template("login.html", error="Invalid credentials")

    session["username"] = user["username"]
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("username"):
        return login_required()

    user = current_user()

    if request.method == "POST":
        bio = request.form.get("bio", "")
        # VULN: stored XSS
        get_db().execute(
            "UPDATE users SET bio = ? WHERE username = ?",
            (bio, user["username"])
        )
        get_db().commit()
        return redirect(url_for("profile"))

    accounts = get_db().execute(
        "SELECT * FROM accounts WHERE owner_username = ?",
        (user["username"],)
    ).fetchall()

    return render_template("profile.html", user=user, accounts=accounts)

@app.route("/api/update", methods=["POST"])
def api_update():
    if not session.get("username"):
        abort(401)

    data = request.get_json(silent=True) or {}

    # VULN: hidden parameter privilege escalation
    if str(data.get("is_admin", "")).lower() == "true":
        get_db().execute(
            "UPDATE users SET is_admin = 1 WHERE username = ?",
            (session["username"],)
        )
        get_db().commit()
        return {"status": "promoted"}, 200

    return {"status": "ok"}, 200

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not session.get("username"):
        return login_required()

    db = get_db()

    if request.method == "POST":
        from_id = int(request.form.get("from_account"))
        to_id = int(request.form.get("to_account"))
        amount = int(request.form.get("amount"))

        from_acc = db.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (from_id,)
        ).fetchone()
        to_acc = db.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (to_id,)
        ).fetchone()

        # VULN: no ownership validation
        if from_acc and to_acc and from_acc["balance"] >= amount:
            db.execute(
                "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                (amount, from_id)
            )
            db.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                (amount, to_id)
            )
            db.execute(
                "INSERT INTO transfers (from_account, to_account, amount, created_by) VALUES (?, ?, ?, ?)",
                (from_id, to_id, amount, session["username"])
            )
            db.commit()

        return redirect(url_for("profile"))

    accounts = db.execute(
        "SELECT id, owner_username, balance FROM accounts ORDER BY id"
    ).fetchall()

    return render_template("transfer.html", user=current_user(), all_accounts=accounts)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = f"SELECT * FROM posts WHERE title LIKE '%{q}%'"

    try:
        posts = get_db().execute(sql).fetchall()
    except Exception as e:
        return render_template("search.html", q=q, posts=[], error=str(e))

    return render_template("search.html", q=q, posts=posts)

@app.route("/fetch")
def fetch():
    if not session.get("username"):
        return login_required()

    url = request.args.get("url", "")
    parsed = urlparse(url)

    # VULN: SSRF
    if parsed.scheme not in ("http", "https"):
        abort(400)

    r = requests.get(url, timeout=3)
    return {"status": r.status_code, "snippet": r.text[:2000]}

@app.route("/admin")
def admin():
    user = current_user()
    if not user or int(user["is_admin"]) != 1:
        abort(403)

    users = get_db().execute(
        "SELECT username, is_admin, bio FROM users"
    ).fetchall()

    transfers = get_db().execute(
        "SELECT * FROM transfers ORDER BY id DESC LIMIT 20"
    ).fetchall()

    return render_template(
        "admin.html",
        user=user,
        users=users,
        transfers=transfers
    )

# ----------------------------
# Passenger entry point
# ----------------------------
application = app
