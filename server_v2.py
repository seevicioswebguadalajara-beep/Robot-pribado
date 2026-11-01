from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from pathlib import Path
import sqlite3
import os
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "cambia-esta-clave-de-sesion-antes-de-publicar")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER", "") == "true"

# Para probar en Pydroid puedes dejar la clave pública en 1234.
# Cambia ADMIN_PASSWORD por una contraseña privada que solo tú conozcas.
ENTRY_PASSWORD = os.environ.get("ENTRY_PASSWORD", "2019")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "2019")

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).with_name("respuestas.db"))))

def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                answer1 TEXT NOT NULL,
                answer2 TEXT NOT NULL,
                answer3 TEXT NOT NULL,
                answer4 TEXT NOT NULL,
                submitted_at TEXT NOT NULL
            )
        """)

def entry_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("entry_ok"):
            return jsonify({"error": "Acceso no autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_ok"):
            return jsonify({"error": "Acceso no autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.route("/", methods=["GET"])
def home():
    if not session.get("entry_ok"):
        return render_template("gate.html")
    return render_template("index.html")

@app.route("/api/entry-login", methods=["POST"])
def entry_login():
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    if not secrets.compare_digest(password, ENTRY_PASSWORD):
        return jsonify({"error": "Clave incorrecta"}), 401
    session.clear()
    session["entry_ok"] = True
    return jsonify({"ok": True})

@app.route("/api/responses", methods=["POST"])
@entry_required
def save_response():
    data = request.get_json(silent=True) or {}
    answers = data.get("answers")
    if not isinstance(answers, list) or len(answers) != 4:
        return jsonify({"error": "Se requieren cuatro campos"}), 400
    if any(not isinstance(x, str) or len(x) > 40 for x in answers):
        return jsonify({"error": "Respuesta no válida"}), 400
    answers = [x.strip() for x in answers]
    if not any(answers):
        return jsonify({"error": "Escribe al menos una posibilidad"}), 400
    with get_db() as db:
        db.execute(
            """INSERT INTO responses
            (answer1, answer2, answer3, answer4, submitted_at)
            VALUES (?, ?, ?, ?, ?)""",
            (*answers, datetime.now().astimezone().isoformat(timespec="seconds"))
        )
    return jsonify({"ok": True})

@app.route("/admin", methods=["GET"])
def admin():
    if not session.get("admin_ok"):
        return render_template("admin_login.html")
    return render_template("admin.html")

@app.route("/api/admin-login", methods=["POST"])
def admin_login():
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"error": "Contraseña incorrecta"}), 401
    session.clear()
    session["admin_ok"] = True
    return jsonify({"ok": True})

@app.route("/api/admin/responses", methods=["GET"])
@admin_required
def list_responses():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM responses ORDER BY id DESC"
        ).fetchall()
    return jsonify([{
        "id": row["id"],
        "answers": [row["answer1"], row["answer2"], row["answer3"], row["answer4"]],
        "submitted_at": row["submitted_at"]
    } for row in rows])

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

# Crear la tabla también cuando Render inicia la app mediante Gunicorn.
init_db()

if __name__ == "__main__":
    # Puerto local 5000: abre http://127.0.0.1:5000 en el navegador del teléfono.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
