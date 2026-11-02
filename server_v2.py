from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import secrets
from datetime import datetime
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "cambia-esta-clave-de-sesion-antes-de-publicar")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER", "") == "true"

# Contraseñas de acceso
ENTRY_PASSWORD = os.environ.get("ENTRY_PASSWORD", "0207")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "2019")

# Configuración de Supabase usando las variables de entorno de Render
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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
    
    # Guardar directamente en la tabla 'responses' de Supabase
    try:
        supabase.table("responses").insert({
            "answer1": answers[0],
            "answer2": answers[1],
            "answer3": answers[2],
            "answer4": answers[3],
            "submitted_at": datetime.now().astimezone().isoformat(timespec="seconds")
        }).execute()
    except Exception as e:
        return jsonify({"error": "Error al guardar en la base de datos"}), 500

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
    # Consultar las respuestas desde Supabase ordenadas de forma descendente por id
    try:
        response = supabase.table("responses").select("*").order("id", desc=True).execute()
        rows = response.data
    except Exception as e:
        return jsonify({"error": "Error al obtener los datos"}), 500

    return jsonify([{
        "id": row["id"],
        "answers": [row["answer1"], row["answer2"], row["answer3"], row["answer4"]],
        "submitted_at": row["submitted_at"]
    } for row in rows])

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
