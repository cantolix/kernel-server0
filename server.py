from datetime import datetime, timedelta
from flask import Flask, jsonify, request
import os
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app = Flask(__name__)
DB = "kernel.db"


def db_exec(query, params=(), fetch=None):
  with sqlite3.connect(DB) as conn:
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    if fetch == "one":
      return cur.fetchone()
    if fetch == "all":
      return cur.fetchall()


def init_db():
  db_exec(
      "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,"
      " username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, status TEXT"
      " DEFAULT 'active', suspension_until TEXT DEFAULT NULL)"
  )
  db_exec(
      "CREATE TABLE IF NOT EXISTS session_logs (id INTEGER PRIMARY KEY"
      " AUTOINCREMENT, username TEXT, target TEXT, case_file TEXT, ip_address"
      " TEXT, timestamp TEXT)"
  )


@app.route("/api/signup", methods=["POST"])
def signup():
  d = request.json
  try:
    db_exec(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (d.get("username"), generate_password_hash(d.get("password"))),
    )
    return jsonify({"message": "OK"}), 201
  except sqlite3.IntegrityError:
    return jsonify({"error": "Error: Username already exists."}), 409


@app.route("/api/login", methods=["POST"])
def login():
  d = request.json
  row = db_exec(
      "SELECT password, status, suspension_until FROM users WHERE username = ?",
      (d.get("username"),),
      fetch="one",
  )
  if not row or not check_password_hash(row[0], d.get("password")):
    return jsonify({"error": "Error: Invalid credentials."}), 401
  if row[1] == "banned":
    return jsonify({"error": "Error: Account is permanently banned."}), 403
  if row[1] == "suspended" and row[2]:
    try:
      if datetime.now() < datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S"):
        return jsonify({"error": f"Error: Suspended until {row[2]}"}), 403
    except:
      pass
  return jsonify({"message": "OK"}), 200


@app.route("/api/change-password", methods=["POST"])
def change_pwd():
  d = request.json
  row = db_exec(
      "SELECT password FROM users WHERE username = ?",
      (d.get("username"),),
      fetch="one",
  )
  if not row or not check_password_hash(row[0], d.get("old_password")):
    return jsonify({"error": "Error: Current password incorrect."}), 401
  db_exec(
      "UPDATE users SET password = ? WHERE username = ?",
      (generate_password_hash(d.get("new_password")), d.get("username")),
  )
  return jsonify({"message": "OK"}), 200


@app.route("/api/moderate", methods=["POST"])
def moderate():
  d = request.json
  target, action = d.get("target_username"), d.get("action")
  if action == "ban":
    db_exec(
        "UPDATE users SET status = 'banned' WHERE username = ?", (target,)
    )
  elif action == "suspend":
    su = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    db_exec(
        "UPDATE users SET status = 'suspended', suspension_until = ? WHERE"
        " username = ?",
        (su, target),
    )
  elif action == "activate":
    db_exec(
        "UPDATE users SET status = 'active', suspension_until = NULL WHERE"
        " username = ?",
        (target,),
    )
  return jsonify({"message": "OK"}), 200


@app.route("/api/log", methods=["POST"])
def log_sess():
  d = request.json
  db_exec(
      "INSERT INTO session_logs (username, target, case_file, ip_address,"
      " timestamp) VALUES (?, ?, ?, ?, ?)",
      (
          d.get("username"),
          d.get("target"),
          d.get("case_file"),
          d.get("ip_address"),
          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      ),
  )
  return jsonify({"message": "OK"}), 200


@app.route("/api/history/<username>", methods=["GET"])
def history(username):
  rows = db_exec(
      "SELECT target, case_file, ip_address, timestamp FROM session_logs WHERE"
      " username = ? ORDER BY id DESC",
      (username,),
      fetch="all",
  )
  return jsonify([{
      "target": r[0],
      "case_file": r[1],
      "ip": r[2],
      "time": r[3],
  } for r in rows]), 200


if __name__ == "__main__":
  init_db()
  app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
