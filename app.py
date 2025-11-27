# ========================= Part 1/4 =========================
import os
import sqlite3
import hashlib
import time
import json
import random
import math
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer

# ------------------------- Config -------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "FriendCoinSecret")

# SendGrid SMTP via Flask-Mail - requires environment variables:
#   SENDGRID_API_KEY  -> your SendGrid API key
#   SENDER_EMAIL     -> your verified sender email in SendGrid
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'apikey'  # fixed for SendGrid SMTP
app.config['MAIL_PASSWORD'] = os.getenv("SENDGRID_API_KEY")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("SENDER_EMAIL")

mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")
serializer = URLSafeTimedSerializer(app.secret_key)

DB = "users.db"

# ------------------------- Simple in-memory blockchain -------------------------
class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending = []
        self.create_genesis()

    def create_genesis(self):
        # genesis block with previous_hash '0'
        self.create_block(previous_hash="0")

    def create_block(self, previous_hash):
        index = len(self.chain) + 1
        timestamp = time.time()
        transactions = list(self.pending)  # copy
        block_content = {
            "index": index,
            "timestamp": timestamp,
            "transactions": transactions,
            "previous_hash": previous_hash
        }
        # compute hash using blake2b
        block_string = json.dumps(block_content, sort_keys=True)
        block_hash = hashlib.blake2b(block_string.encode(), digest_size=32).hexdigest()
        block_content["hash"] = block_hash
        # append and clear pending
        self.chain.append(block_content)
        self.pending = []
        return block_content

    def add_transaction(self, sender, receiver, amount):
        tx = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        self.pending.append(tx)
        return tx

    def last_hash(self):
        if not self.chain:
            return "0"
        return self.chain[-1]["hash"]

# instantiate blockchain
blockchain = Blockchain()

# ------------------------- DB init -------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    password TEXT,
                    wallet TEXT UNIQUE,
                    private_key TEXT,
                    balance REAL DEFAULT 100.0,
                    mined_balance REAL DEFAULT 0.0,
                    email_verified INTEGER DEFAULT 0
                )''')
    # transactions table (simple ledger history)
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT,
                    receiver TEXT,
                    amount REAL,
                    timestamp TEXT
                )''')
    # mining sessions table
    c.execute('''CREATE TABLE IF NOT EXISTS mining_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet TEXT UNIQUE,
                    start_ts INTEGER,
                    active INTEGER DEFAULT 0
                )''')
    conn.commit()
    conn.close()

init_db()

# ------------------------- Utilities -------------------------
def send_email(to_email, subject, body):
    try:
        msg = Message(subject, recipients=[to_email])
        msg.body = body
        mail.send(msg)
        app.logger.info("Email sent to %s", to_email)
        return True
    except Exception as e:
        app.logger.error("Email send error: %s", e)
        return False

def send_otp_email(email, otp):
    body = f"Your FriendCoin OTP: {otp}\nThis OTP expires in 10 minutes."
    return send_email(email, "FriendCoin OTP", body)

def send_privatekey_email(email, private_key):
    body = f"Your FriendCoin Private Key:\n\n{private_key}\n\nKeep it safe!"
    return send_email(email, "FriendCoin — Private Key", body)

def send_tx_emails(sender_email, receiver_email, amount, sender_wallet, receiver_wallet):
    # sender email
    send_email(sender_email, "FriendCoin — Sent",
               f"You sent {amount} FRC.\nFrom: {sender_wallet}\nTo: {receiver_wallet}\nIf you didn't authorize this, contact admin.")
    # receiver email
    send_email(receiver_email, "FriendCoin — Received",
               f"You received {amount} FRC.\nFrom: {sender_wallet}\nTo: {receiver_wallet}\nCheck your dashboard for details.")

def generate_wallet():
    return hashlib.blake2b(str(time.time()).encode(), digest_size=16).hexdigest()

def generate_private_key():
    return hashlib.blake2b(os.urandom(32), digest_size=32).hexdigest()

# ------------------------- DB helpers -------------------------
def get_user(username_or_email):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, password, wallet, private_key, balance, mined_balance, email_verified FROM users WHERE username=? OR email=?",
        (username_or_email, username_or_email)
    )
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_wallet(wallet):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, password, wallet, private_key, balance, mined_balance, email_verified FROM users WHERE wallet=?",
        (wallet,)
    )
    row = c.fetchone()
    conn.close()
    return row

def update_balance(wallet, amount):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET balance=? WHERE wallet=?", (amount, wallet))
    conn.commit()
    conn.close()

def update_mined_balance(wallet, amount):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET mined_balance=? WHERE wallet=?", (amount, wallet))
    conn.commit()
    conn.close()

def save_transaction_db(sender, receiver, amount):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, ?)",
              (sender, receiver, amount, ts))
    conn.commit()
    conn.close()

def get_transactions(wallet):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT sender, receiver, amount, timestamp FROM transactions WHERE sender=? OR receiver=? ORDER BY id DESC", (wallet, wallet))
    rows = c.fetchall()
    conn.close()
    return rows

# ------------------------- Mining helpers -------------------------
MINING_INTERVAL_SECONDS = 300  # 5 minutes -> 1 FRC
MINING_RATE_PER_INTERVAL = 1.0  # 1 FRC per 5 minutes

def start_mining_session(wallet):
    now = int(time.time())
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO mining_sessions (wallet, start_ts, active) VALUES (?, ?, ?)", (wallet, now, 1))
    conn.commit()
    conn.close()

def stop_mining_session(wallet):
    # compute mined so far and accumulate mined_balance, then mark inactive
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT start_ts, active FROM mining_sessions WHERE wallet=?", (wallet,))
    row = c.fetchone()
    if not row:
        conn.close()
        return 0.0
    start_ts, active = row
    if not start_ts or active == 0:
        conn.close()
        return 0.0
    now = int(time.time())
    elapsed = now - start_ts
    intervals = elapsed // MINING_INTERVAL_SECONDS
    mined = intervals * MINING_RATE_PER_INTERVAL
    # add to mined_balance
    c.execute("SELECT mined_balance FROM users WHERE wallet=?", (wallet,))
    cur = c.fetchone()
    cur_mined = cur[0] if cur else 0.0
    new_mined = round(cur_mined + mined, 8)
    c.execute("UPDATE users SET mined_balance=? WHERE wallet=?", (new_mined, wallet))
    # mark session inactive (set active=0)
    c.execute("UPDATE mining_sessions SET active=0 WHERE wallet=?", (wallet,))
    conn.commit()
    conn.close()
    return mined

def compute_current_mined(wallet):
    # compute on-the-fly mined coins since start (without persisting)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT start_ts, active FROM mining_sessions WHERE wallet=?", (wallet,))
    row = c.fetchone()
    c.execute("SELECT mined_balance FROM users WHERE wallet=?", (wallet,))
    cur = c.fetchone()
    cur_mined = cur[0] if cur else 0.0
    conn.close()
    if not row:
        return cur_mined
    start_ts, active = row
    if not start_ts or active == 0:
        return cur_mined
    elapsed = int(time.time()) - start_ts
    intervals = elapsed // MINING_INTERVAL_SECONDS
    mined_now = intervals * MINING_RATE_PER_INTERVAL
    return round(cur_mined + mined_now, 8)
# ========================= End of Part 1/4 =========================

# ========================= Part 2/4 =========================
# ------------------------- API endpoints for AJAX -------------------------
@app.route("/api/wallet/<wallet>")
def api_wallet(wallet):
    u = get_user_by_wallet(wallet)
    if not u:
        return jsonify({"error": "not found"}), 404
    # compute current mined (including running session)
    mined = compute_current_mined(wallet)
    return jsonify({"wallet": u[4], "balance": u[6], "mined_balance": mined})

@app.route("/api/txs/<wallet>")
def api_txs(wallet):
    rows = get_transactions(wallet)
    txs = [{"sender": r[0], "receiver": r[1], "amount": r[2], "time": r[3]} for r in rows]
    return jsonify({"txs": txs})

# ------------------------- Routes: auth and pages -------------------------
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# Register (POST creates pending user and sends OTP)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            return render_template("register.html", error="Please fill all fields.")
        if get_user(username) or get_user(email):
            return render_template("register.html", error="Username or Email already exists.")
        wallet = generate_wallet()
        private_key = generate_private_key()
        otp = str(random.randint(100000, 999999))
        session["pending_user"] = {
            "username": username,
            "email": email,
            "password": password,
            "wallet": wallet,
            "private_key": private_key,
            "otp": otp,
            "otp_time": int(time.time())
        }
        if not send_otp_email(email, otp):
            return render_template("register.html", error="Failed to send OTP email. Check SendGrid configuration.")
        app.logger.info("Sent OTP to %s", email)
        return redirect(url_for("verify_register"))
    return render_template("register.html")

@app.route("/verify-register", methods=["GET", "POST"])
def verify_register():
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("register"))
    if request.method == "POST":
        user_otp = request.form.get("otp", "").strip()
        if not user_otp:
            return render_template("verify_register.html", error="Enter OTP.")
        if int(time.time()) - pending.get("otp_time", 0) > 600:
            session.pop("pending_user", None)
            return render_template("register.html", error="OTP expired. Please register again.")
        if user_otp != pending.get("otp"):
            return render_template("verify_register.html", error="Invalid OTP.")
        # insert user
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password, wallet, private_key, email_verified) VALUES (?, ?, ?, ?, ?, 1)",
                  (pending["username"], pending["email"], pending["password"], pending["wallet"], pending["private_key"]))
        conn.commit()
        conn.close()
        pk = pending["private_key"]
        wallet = pending["wallet"]
        session.pop("pending_user", None)
        return render_template("register_success.html", wallet=wallet, private_key=pk)
    return render_template("verify_register.html")

# Login (password check, then send OTP)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_input = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(user_input)
        if not user:
            return render_template("login.html", error="Invalid login.")
        if user[3] != password:
            return render_template("login.html", error="Incorrect password.")
        otp = str(random.randint(100000, 999999))
        session["login_user"] = user[1]
        session["login_otp"] = otp
        session["login_otp_time"] = int(time.time())
        if not send_otp_email(user[2], otp):
            return render_template("login.html", error="Failed to send OTP email. Check SendGrid configuration.")
        return redirect(url_for("verify_login"))
    return render_template("login.html")

@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():
    if request.method == "POST":
        otp_entered = request.form.get("otp", "").strip()
        if not otp_entered:
            return render_template("verify_login.html", error="Enter OTP.")
        if int(time.time()) - session.get("login_otp_time", 0) > 600:
            session.pop("login_otp", None)
            session.pop("login_user", None)
            return render_template("login.html", error="OTP expired. Please login again.")
        if otp_entered != session.get("login_otp"):
            return render_template("verify_login.html", error="Invalid OTP")
        session["username"] = session["login_user"]
        session.pop("login_user", None)
        session.pop("login_otp", None)
        session.pop("login_otp_time", None)
        return redirect(url_for("dashboard"))
    return render_template("verify_login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

# Dashboard page
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    user = get_user(session["username"])
    if not user:
        session.pop("username", None)
        return redirect(url_for("login"))
    txs = get_transactions(user[4])
    return render_template("dashboard.html",
                           username=user[1],
                           wallet=user[4],
                           balance=user[6],
                           mined_balance=compute_current_mined(user[4]),
                           tx_history=txs)

# Profile page
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    user = get_user(session["username"])
    return render_template("profile.html", username=user[1], wallet=user[4], balance=user[6])

@app.route("/send_private_key", methods=["POST"])
def send_private_key():
    if "username" not in session:
        return redirect(url_for("login"))
    password = request.form.get("password") or request.form.get("password_confirm")
    user = get_user(session["username"])
    if not password or user[3] != password:
        return render_template("profile.html", error="Wrong password.", username=user[1], wallet=user[4], balance=user[6])
    if send_privatekey_email(user[2], user[5]):
        flash("Private key sent to your registered email.")
    else:
        flash("Failed to send private key email. Check email configuration.")
    return redirect(url_for("profile"))
# ========================= End of Part 2/4 =========================

# ========================= Part 3/4 =========================
# Explorer
@app.route("/explorer")
def explorer():
    # show the in-memory blockchain
    chain = blockchain.chain
    return render_template("explorer.html", chain=chain)

# ------------------------- Transaction endpoints -------------------------
@app.route("/send_ajax", methods=["POST"])
def send_ajax():
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}), 401
    data = request.get_json() or {}
    receiver_wallet = (data.get("receiver_wallet") or "").strip()
    try:
        amount = float(data.get("amount", 0))
    except:
        return jsonify({"status":"error","message":"Invalid amount"}), 400
    private_key_entered = (data.get("private_key") or "").strip()

    sender = get_user(session["username"])
    if not sender:
        return jsonify({"status":"error","message":"Sender not found"}), 400

    sender_wallet = sender[4]
    sender_priv = sender[5]
    sender_balance = sender[6]

    # check private key
    if private_key_entered != sender_priv:
        return jsonify({"status":"error","message":"Invalid private key"}), 403

    # receiver exists
    receiver = get_user_by_wallet(receiver_wallet)
    if not receiver:
        return jsonify({"status":"error","message":"Receiver not found"}), 400

    # validations
    if amount <= 0:
        return jsonify({"status":"error","message":"Amount must be positive"}), 400
    if sender_balance < amount:
        return jsonify({"status":"error","message":"Insufficient balance"}), 400

    # update DB balances
    update_balance(sender_wallet, round(sender_balance - amount, 8))
    update_balance(receiver_wallet, round(receiver[6] + amount, 8))

    # save tx to DB
    save_transaction_db(sender_wallet, receiver_wallet, amount)

    # add to blockchain pending and create a block (simple demo: create block per tx)
    blockchain.add_transaction(sender_wallet, receiver_wallet, amount)
    last_hash = blockchain.last_hash()
    blockchain.create_block(previous_hash=last_hash)

    # send emails (best-effort)
    try:
        send_tx_emails(sender[2], receiver[2], amount, sender_wallet, receiver_wallet)
    except Exception as e:
        app.logger.error("tx email error: %s", e)

    # emit socket to refresh other clients
    try:
        socketio.emit("update_dashboard", {"sender": sender_wallet, "receiver": receiver_wallet, "amount": amount}, broadcast=True)
    except Exception as e:
        app.logger.error("socket emit error: %s", e)

    return jsonify({"status":"success","message":"Transaction completed","sender_balance":get_user_by_wallet(sender_wallet)[6],"receiver_balance":get_user_by_wallet(receiver_wallet)[6]})

# classic form fallback (keeps compatibility)
@app.route("/send", methods=["POST"])
def send():
    if "username" not in session:
        return redirect(url_for("login"))
    sender = get_user(session["username"])
    sender_wallet = sender[4]
    try:
        amount = float(request.form.get("amount", "0"))
    except:
        flash("Invalid amount.")
        return redirect(url_for("dashboard"))
    receiver_wallet = request.form.get("receiver_wallet", "").strip()
    receiver = get_user_by_wallet(receiver_wallet)
    if not receiver:
        flash("Receiver not found.")
        return redirect(url_for("dashboard"))
    if sender[6] < amount:
        flash("Insufficient balance.")
        return redirect(url_for("dashboard"))
    update_balance(sender_wallet, round(sender[6] - amount, 8))
    update_balance(receiver_wallet, round(receiver[6] + amount, 8))
    save_transaction_db(sender_wallet, receiver_wallet, amount)
    blockchain.add_transaction(sender_wallet, receiver_wallet, amount)
    last_hash = blockchain.last_hash()
    blockchain.create_block(previous_hash=last_hash)
    try:
        send_tx_emails(sender[2], receiver[2], amount, sender_wallet, receiver_wallet)
    except Exception as e:
        app.logger.error("tx email error: %s", e)
    try:
        socketio.emit("update_dashboard", {"sender": sender_wallet, "receiver": receiver_wallet, "amount": amount}, broadcast=True)
    except Exception as e:
        app.logger.error("socket emit error: %s", e)
    return redirect(url_for("dashboard"))
# ========================= End of Part 3/4 =========================

# ========================= Part 4/4 =========================
# ------------------------- Mining endpoints -------------------------
@app.route("/mining")
def mining():
    if "username" not in session:
        return redirect(url_for("login"))
    user = get_user(session["username"])
    # compute current mined amount (includes running sessions)
    current_mined = compute_current_mined(user[4])
    # check if session active
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT active FROM mining_sessions WHERE wallet=?", (user[4],))
    row = c.fetchone()
    active = bool(row[0]) if row else False
    conn.close()
    return render_template("mining.html", username=user[1], wallet=user[4], mining_balance=current_mined, rate=MINING_RATE_PER_INTERVAL, active=active)

@app.route("/start-mining", methods=["POST"])
def start_mining():
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}), 401
    user = get_user(session["username"])
    start_mining_session(user[4])
    return jsonify({"status":"success","message":"Mining started"})

@app.route("/stop-mining", methods=["POST"])
def stop_mining():
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}), 401
    user = get_user(session["username"])
    mined = stop_mining_session(user[4])
    return jsonify({"status":"success","mined": mined, "message":"Mining stopped"})

@app.route("/withdraw-mining", methods=["POST"])
def withdraw_mining():
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}), 401
    user = get_user(session["username"])
    wallet = user[4]
    # compute mined (this returns current mined including running sessions)
    mined_now = compute_current_mined(wallet)
    # persist: add mined_now to main balance and zero out mined_balance, reset mining start_ts if active
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # set mined_balance to 0
    c.execute("UPDATE users SET mined_balance=0 WHERE wallet=?", (wallet,))
    # if there is a running session, reset its start_ts to now to avoid double counting
    c.execute("SELECT start_ts, active FROM mining_sessions WHERE wallet=?", (wallet,))
    row = c.fetchone()
    if row and row[1] == 1:
        c.execute("UPDATE mining_sessions SET start_ts=? WHERE wallet=?", (int(time.time()), wallet))
    conn.commit()
    conn.close()
    # add mined_now to main balance
    new_balance = round(user[6] + mined_now, 8)
    update_balance(wallet, new_balance)
    return jsonify({"status":"success","message":f"{mined_now} FRC transferred to main wallet","main_balance":new_balance})

# ------------------------- Run -------------------------
if __name__ == "__main__":
    if not app.config['MAIL_PASSWORD'] or not app.config['MAIL_DEFAULT_SENDER']:
        app.logger.warning("SENDGRID_API_KEY and/or SENDER_EMAIL not set in environment. Emails will fail until configured.")

    port = int(os.environ.get("PORT", 5000))  # Render gives PORT
    socketio.run(app, host="0.0.0.0", port=port, debug=True)



