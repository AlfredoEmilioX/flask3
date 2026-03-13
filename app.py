from flask import Flask, render_template, request, redirect, jsonify
from db import get_connection

import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
import os
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")



def create_access_token(user_id: int, role: str, expires_minutes: int = 60) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _get_bearer_token()
        if not token:
            return jsonify({"status": "error", "message": "Token requerido (Authorization: Bearer <token>)"}), 401

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Token inválido"}), 401

        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    @jwt_required
    def wrapper(*args, **kwargs):
        role = getattr(request, "user", {}).get("role")
        if role != "admin":
            return jsonify({"status": "error", "message": "Acceso denegado: solo administrador"}), 403
        return fn(*args, **kwargs)

    return wrapper


# ==========================================================
# AUTH - LOGIN (JWT)
# ==========================================================
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"status": "error", "message": "email y password son obligatorios"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, nombre, email, password_hash, role FROM usuarios WHERE email = %s", (email,))
    usuario = cursor.fetchone()
    cursor.close()
    conn.close()

    if usuario is None:
        return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401

    if not check_password_hash(usuario["password_hash"], password):
        return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401

    token = create_access_token(usuario["id"], usuario["role"], expires_minutes=60)

    return jsonify({
        "status": "ok",
        "access_token": token,
        "user": {
            "id": usuario["id"],
            "nombre": usuario["nombre"],
            "email": usuario["email"],
            "role": usuario["role"],
        }
    })


# ================== INICIO ==================
@app.route('/', methods=['GET', 'POST'])
def inicio():
    nombre = None
    if request.method == 'POST':
        nombre = request.form['nombre']
    return render_template('index.html', nombre=nombre)


# ================== USUARIOS (WEB) ==================
@app.route('/usuarios')
def usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email, role, created_at FROM usuarios")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('usuarios.html', usuarios=data)


@app.route('/usuarios/nuevo')
def nuevo_usuario():
    return render_template('usuarios_form.html')


@app.route('/usuarios/guardar', methods=['POST'])
def guardar_usuario():
    nombre = request.form['nombre']
    email = request.form['email']

    default_password = "Alumno123*"
    password_hash = generate_password_hash(default_password)
    role = "alumno"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (nombre, email, password_hash, role) VALUES (%s, %s, %s, %s)",
        (nombre, email, password_hash, role)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/usuarios')


@app.route('/usuarios/editar/<int:id>')
def editar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email, role FROM usuarios WHERE id=%s", (id,))
    usuario = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('usuarios_form.html', usuario=usuario)


@app.route('/usuarios/actualizar/<int:id>', methods=['POST'])
def actualizar_usuario(id):
    nombre = request.form['nombre']
    email = request.form['email']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s", (nombre, email, id))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/usuarios')


@app.route('/usuarios/eliminar/<int:id>')
def eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/usuarios')


# ================== API USUARIOS (JSON) ==================
@app.route("/api/usuarios", methods=["GET"])
def api_listar_usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email, role, created_at FROM usuarios")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"status": "ok", "data": data})


@app.route("/api/usuarios/<int:id>", methods=["GET"])
def api_obtener_usuario(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email, role, created_at FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    cursor.close()
    conn.close()

    if usuario is None:
        return jsonify({"status": "error", "message": "Usuario no encontrado"}), 404

    return jsonify({"status": "ok", "data": usuario})


@app.route("/api/usuarios", methods=["POST"])
@admin_required
def api_crear_usuario():
    data = request.get_json(silent=True) or {}
    nombre = data.get("nombre")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "alumno")

    if not nombre or not email or not password:
        return jsonify({"status": "error", "message": "nombre, email y password son obligatorios"}), 400

    if role not in ["admin", "alumno"]:
        return jsonify({"status": "error", "message": "role inválido"}), 400

    password_hash = generate_password_hash(password)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO usuarios (nombre, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (nombre, email, password_hash, role)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return jsonify({"status": "error", "message": "No se pudo crear usuario (¿email duplicado?)"}), 400
    finally:
        cursor.close()
        conn.close()

    return jsonify({"status": "ok", "message": "Usuario creado correctamente"}), 201


@app.route("/api/usuarios/<int:id>", methods=["DELETE"])
@admin_required
def api_eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "ok", "message": "Usuario eliminado"})


# ================== CURSOS (WEB) ==================
@app.route('/cursos')
def cursos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('cursos.html', cursos=data)


@app.route('/cursos/nuevo')
def nuevo_curso():
    return render_template('cursos_form.html')


@app.route('/cursos/guardar', methods=['POST'])
def guardar_curso():
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)", (nombre, descripcion))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/cursos')


@app.route('/cursos/editar/<int:id>')
def editar_curso(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos WHERE id=%s", (id,))
    curso = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('cursos_form.html', curso=curso)


@app.route('/cursos/actualizar/<int:id>', methods=['POST'])
def actualizar_curso(id):
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE cursos SET nombre=%s, descripcion=%s WHERE id=%s", (nombre, descripcion, id))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/cursos')


@app.route('/cursos/eliminar/<int:id>')
def eliminar_curso(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/cursos')


# ================== API CURSOS (JSON) ==================
@app.route("/api/cursos", methods=["GET"])
def api_listar_cursos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"status": "ok", "data": data})


@app.route("/api/cursos/<int:id>", methods=["GET"])
def api_obtener_curso(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos WHERE id = %s", (id,))
    curso = cursor.fetchone()
    cursor.close()
    conn.close()

    if curso is None:
        return jsonify({"status": "error", "message": "Curso no encontrado"}), 404

    return jsonify({"status": "ok", "data": curso})


@app.route("/api/cursos", methods=["POST"])
@admin_required
def api_crear_curso():
    data = request.get_json(silent=True) or {}
    nombre = data.get("nombre")
    descripcion = data.get("descripcion", "")

    if not nombre:
        return jsonify({"status": "error", "message": "nombre es obligatorio"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)",
        (nombre, descripcion)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "ok", "message": "Curso creado correctamente"}), 201


@app.route("/api/cursos/<int:id>", methods=["DELETE"])
@admin_required
def api_eliminar_curso(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso eliminado"})


# ================== INSCRIPCIONES (WEB) ==================
@app.route('/inscripciones')
def inscripciones():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos c ON i.curso_id = c.id
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('inscripciones.html', inscripciones=data)


@app.route('/inscripciones/nueva')
def nueva_inscripcion():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    cursor.execute("SELECT * FROM cursos")
    cursos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('inscripcion_form.html', usuarios=usuarios, cursos=cursos)


@app.route('/inscripciones/guardar', methods=['POST'])
def guardar_inscripcion():
    usuario_id = request.form['usuario_id']
    curso_id = request.form['curso_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion) VALUES (%s, %s, CURDATE())",
        (usuario_id, curso_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/inscripciones')


# ================== API INSCRIPCIONES (JSON) ==================
@app.route("/api/inscripciones", methods=["GET"])
def api_listar_inscripciones():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, i.usuario_id, i.curso_id, i.fecha_inscripcion,
               u.nombre AS usuario, c.nombre AS curso
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos c ON i.curso_id = c.id
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"status": "ok", "data": data})


@app.route("/api/inscripciones/<int:id>", methods=["GET"])
def api_obtener_inscripcion(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, i.usuario_id, i.curso_id, i.fecha_inscripcion,
               u.nombre AS usuario, c.nombre AS curso
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos c ON i.curso_id = c.id
        WHERE i.id = %s
    """, (id,))
    inscripcion = cursor.fetchone()
    cursor.close()
    conn.close()

    if inscripcion is None:
        return jsonify({"status": "error", "message": "Inscripción no encontrada"}), 404

    return jsonify({"status": "ok", "data": inscripcion})


@app.route("/api/inscripciones", methods=["POST"])
@jwt_required
def api_crear_inscripcion():
    data = request.get_json(silent=True) or {}
    usuario_id = data.get("usuario_id")
    curso_id = data.get("curso_id")

    if not usuario_id or not curso_id:
        return jsonify({"status": "error", "message": "usuario_id y curso_id son obligatorios"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion) VALUES (%s, %s, CURDATE())",
            (usuario_id, curso_id)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return jsonify({"status": "error", "message": "No se pudo crear inscripción (¿duplicada?)"}), 400
    finally:
        cursor.close()
        conn.close()

    return jsonify({"status": "ok", "message": "Inscripción creada correctamente"}), 201


@app.route("/api/inscripciones/<int:id>", methods=["DELETE"])
@admin_required
def api_eliminar_inscripcion(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "ok", "message": "Inscripción eliminada"})


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/prueba-api")
def prueba_api():
    return render_template("prueba_api.html")


if __name__ == '__main__':
    app.run(debug=True)