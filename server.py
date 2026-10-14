from datetime import datetime
from flask import Flask, jsonify, request
import os
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app = Flask(__name__)
DB_NAME = "kernel.db"


def init_db():
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
  cursor.execute("""
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
  conn.close()


@app.route("/api/signup", methods=["POST"])
def signup():
  data = request.json
  try:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (data.get("username"), generate_password_hash(data.get("password"))),
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "User created successfully"}), 201
  except sqlite3.IntegrityError:
    return jsonify({"error": "Username already exists"}), 409


@app.route("/api/login", methods=["POST"])
def login():
  data = request.json
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute(
      "SELECT password FROM users WHERE username = ?", (data.get("username"),)
  )
  row = cursor.fetchone()
  conn.close()
  if row and check_password_hash(row[0], data.get("password")):
    return jsonify({"message": "Login successful"}), 200
  return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/log", methods=["POST"])
def log_session():
  data = request.json
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute(
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
  conn.close()
  return jsonify({"message": "Log recorded"}), 200


@app.route("/api/logs", methods=["GET"])
def view_logs():
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute("SELECT * FROM session_logs ORDER BY id DESC")
  rows = cursor.fetchall()
  conn.close()
  return jsonify([{
      "id": r[0],
      "admin": r[1],
      "target": r[2],
      "case_file": r[3],
      "ip": r[4],
      "time": r[5],
  } for r in rows]), 200


if __name__ == "__main__":
  init_db()
  port = int(os.environ.get("PORT", 5000))
  app.run(host="0.0.0.0", port=port)