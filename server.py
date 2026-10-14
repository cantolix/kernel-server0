from datetime import datetime, timedelta
from flask import Flask, jsonify, request
import os
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app = Flask(__name__)
DB_NAME = "kernel.db"


def get_db():
  conn = sqlite3.connect(DB_NAME)
  conn.row_factory = sqlite3.Row
  return conn


def init_db():
  with get_db() as conn:
    conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                suspension_until TEXT DEFAULT NULL
            )
        """)
    conn.execute("""
            CREATE TABLE IF NOT EXISTS session_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                target TEXT,
                case_file TEXT,
                ip_address TEXT,
                timestamp TEXT
            )
        """)
    conn.commit()


@app.route("/api/signup", methods=["POST"])
def signup():
  data = request.json or {}
  username = data.get("username", "").strip()
  password = data.get("password", "").strip()

  if not username or not password:
    return jsonify({"error": "Error: Username and password required."}), 400

  try:
    with get_db() as conn:
      conn.execute(
          "INSERT INTO users (username, password) VALUES (?, ?)",
          (username, generate_password_hash(password)),
      )
      conn.commit()
    return jsonify({"message": "OK"}), 201
  except sqlite3.IntegrityError:
    return jsonify({"error": "Error: Username already exists."}), 409


@app.route("/api/login", methods=["POST"])
def login():
  data = request.json or {}
  username = data.get("username", "").strip()
  password = data.get("password", "").strip()

  with get_db() as conn:
    row = conn.execute(
        "SELECT password, status, suspension_until FROM users WHERE username ="
        " ?",
        (username,),
    ).fetchone()

  if not row or not check_password_hash(row["password"], password):
    return jsonify({"error": "Error: Invalid credentials."}), 401

  if row["status"] == "banned":
    return jsonify({"error": "Error: Account is permanently banned."}), 403

  if row["status"] == "suspended" and row["suspension_until"]:
    try:
      susp_time = datetime.strptime(
          row["suspension_until"], "%Y-%m-%d %H:%M:%S"
      )
      if datetime.now() < susp_time:
        return (
            jsonify({
                "error": (
                    f"Error: Suspended until {row['suspension_until']}"
                )
            }),
            403,
        )
    except Exception:
      pass

  return jsonify({"message": "OK"}), 200


@app.route("/api/users", methods=["GET"])
def get_users():
  with get_db() as conn:
    rows = conn.execute(
        "SELECT username, status, suspension_until FROM users"
    ).fetchall()
  return (
      jsonify([{
          "username": r["username"],
          "status": r["status"],
          "suspension_until": r["suspension_until"],
      } for r in rows]),
      200,
  )


@app.route("/api/change-password", methods=["POST"])
def change_password():
  data = request.json or {}
  username = data.get("username", "").strip()
  old_pwd = data.get("old_password", "").strip()
  new_pwd = data.get("new_password", "").strip()

  with get_db() as conn:
    row = conn.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    ).fetchone()

  if not row or not check_password_hash(row["password"], old_pwd):
    return jsonify({"error": "Error: Current password incorrect."}), 401

  with get_db() as conn:
    conn.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (generate_password_hash(new_pwd), username),
    )
    conn.commit()

  return jsonify({"message": "OK"}), 200


@app.route("/api/moderate", methods=["POST"])
def moderate():
  data = request.json or {}
  target = data.get("target_username", "").strip()
  action = data.get("action", "").strip()

  if not target:
    return jsonify({"error": "Error: Target username required."}), 400

  with get_db() as conn:
    if action == "ban":
      conn.execute(
          "UPDATE users SET status = 'banned' WHERE username = ?", (target,)
      )
    elif action == "suspend":
      susp_time = (datetime.now() + timedelta(minutes=15)).strftime(
          "%Y-%m-%d %H:%M:%S"
      )
      conn.execute(
          "UPDATE users SET status = 'suspended', suspension_until = ? WHERE"
          " username = ?",
          (susp_time, target),
      )
    elif action == "activate":
      conn.execute(
          "UPDATE users SET status = 'active', suspension_until = NULL WHERE"
          " username = ?",
          (target,),
      )
    conn.commit()

  return jsonify({"message": "OK"}), 200


@app.route("/api/log", methods=["POST"])
def log_session():
  data = request.json or {}
  with get_db() as conn:
    conn.execute(
        """
            INSERT INTO session_logs (username, target, case_file, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
        (
            data.get("username"),
            data.get("target"),
            data.get("case_file"),
            data.get("ip_address"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
  return jsonify({"message": "OK"}), 200


@app.route("/api/history/<username>", methods=["GET"])
def user_history(username):
  with get_db() as conn:
    rows = conn.execute(
        "SELECT target, case_file, ip_address, timestamp FROM session_logs WHERE"
        " username = ? ORDER BY id DESC",
        (username,),
    ).fetchall()
  return (
      jsonify([{
          "target": r["target"],
          "case_file": r["case_file"],
          "ip": r["ip_address"],
          "time": r["timestamp"],
      } for r in rows]),
      200,
  )


if __name__ == "__main__":
  init_db()
  port = int(os.environ.get("PORT", 5000))
  app.run(host="0.0.0.0", port=port)
