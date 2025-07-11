# -*- coding: utf-8 -*-

# -----------------------------------------------------------------------------
# API Syra - Versão Incrementada com JWT e Novas Funcionalidades
# -----------------------------------------------------------------------------
# Dependências: Flask, Flask-Cors, pyotp, qrcode[pil], PyJWT
# Para instalar: pip install Flask Flask-Cors pyotp "qrcode[pil]" PyJWT
# -----------------------------------------------------------------------------

import sqlite3
import pyotp
import qrcode
import io
import base64
import jwt
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Configuração ---
DB_NAME = "syra.db"
APP_NAME = "Syra"
JWT_SECRET_KEY = "sua-chave-secreta-super-segura-e-longa"
JWT_ALGORITHM = "HS256"

app = Flask(__name__)
CORS(app)
pending_registrations = {}

# --- Banco de Dados ---
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                friends TEXT DEFAULT '[]',
                exp INTEGER DEFAULT 0,
                achievements TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS db_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                node TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')
        conn.commit()
        print(f"Banco de dados '{DB_NAME}' pronto para uso com tabelas 'users' e 'db_temp'.")
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")
    finally:
        if conn:
            conn.close()

# --- Autenticação JWT ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"error": "Formato de token inválido. Use 'Bearer <token>'."}), 401

        if not token:
            return jsonify({"error": "Token de autenticação não fornecido"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            conn = get_db_connection()
            current_user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
            conn.close()
            if not current_user:
                return jsonify({"error": "Usuário do token não encontrado"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado. Faça login novamente."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido."}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# --- Registro ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or not data['username'].strip():
        return jsonify({"error": "O campo 'username' é obrigatório"}), 400

    username = data['username'].strip().lower()
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user:
        return jsonify({"error": "Este nome de usuário já está em uso"}), 409

    secret = pyotp.random_base32()
    pending_registrations[username] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({
        "message": "Escaneie o QR Code e use a rota /verify para confirmar.",
        "secret_backup_key": secret,
        "qr_code_image": f"data:image/png;base64,{qr_code_b64}"
    })

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    if not data or 'username' not in data or 'totp_code' not in data:
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    if username not in pending_registrations:
        return jsonify({"error": "Registro não iniciado ou expirado. Use /register primeiro."}), 404

    secret = pending_registrations[username]
    totp = pyotp.TOTP(secret)

    if totp.verify(totp_code):
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, secret) VALUES (?, ?)', (username, secret))
            conn.commit()
            del pending_registrations[username]
            return jsonify({"status": "success", "message": "Usuário registrado com sucesso!"})
        except sqlite3.IntegrityError:
            return jsonify({"error": "Este nome de usuário já está em uso"}), 409
        finally:
            if conn:
                conn.close()
    else:
        return jsonify({"error": "Código de verificação inválido"}), 401

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'totp_code' not in data:
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    user = conn.execute('SELECT secret FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404

    secret = user['secret']
    totp = pyotp.TOTP(secret)

    if totp.verify(totp_code):
        token = jwt.encode({
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        # CORREÇÃO: converte bytes em string
        token = token if isinstance(token, str) else token.decode('utf-8')

        return jsonify({
            "status": "success",
            "message": "Login bem-sucedido!",
            "token": token
        })
    else:
        return jsonify({"error": "Código de login inválido"}), 401

# --- Perfil ---
@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    user_data = dict(current_user)
    del user_data['secret']
    del user_data['id']
    user_data['friends'] = json.loads(user_data['friends'])
    user_data['achievements'] = json.loads(user_data['achievements'])
    return jsonify(user_data)

# --- Listagem de usuários ---
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM users').fetchall()
    conn.close()
    return jsonify({"users": [row['username'] for row in users]})

# --- TEMP NODES ---
@app.route('/temp_nodes', methods=['POST'])
@token_required
def add_temp_node(current_user):
    data = request.get_json()
    if not data or 'node' not in data or not data['node'].strip():
        return jsonify({"error": "O campo 'node' é obrigatório"}), 400

    conn = get_db_connection()
    conn.execute('INSERT INTO db_temp (username, node) VALUES (?, ?)', (current_user['username'], data['node'].strip()))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Nó adicionado com sucesso"}), 201

@app.route('/temp_nodes', methods=['GET'])
@token_required
def get_temp_nodes(current_user):
    conn = get_db_connection()
    rows = conn.execute('SELECT id, node FROM db_temp WHERE username = ?', (current_user['username'],)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/temp_nodes/<int:node_id>', methods=['DELETE'])
@token_required
def delete_temp_node(current_user, node_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM db_temp WHERE id = ? AND username = ?', (node_id, current_user['username']))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    if deleted == 0:
        return jsonify({"error": "Nó não encontrado ou não pertence a este usuário."}), 404
    return jsonify({"status": "success", "message": f"Nó com ID {node_id} deletado."})

# --- Amigos ---
@app.route('/friends', methods=['POST'])
@token_required
def add_friend(current_user):
    data = request.get_json()
    if not data or 'friend_username' not in data:
        return jsonify({"error": "O campo 'friend_username' é obrigatório."}), 400

    friend_username = data['friend_username'].strip().lower()
    if friend_username == current_user['username']:
        return jsonify({"error": "Você não pode adicionar a si mesmo como amigo."}), 400

    conn = get_db_connection()
    friend = conn.execute('SELECT username FROM users WHERE username = ?', (friend_username,)).fetchone()
    if not friend:
        conn.close()
        return jsonify({"error": "Usuário amigo não encontrado."}), 404

    current_friends = json.loads(current_user['friends'])
    if friend_username in current_friends:
        conn.close()
        return jsonify({"error": "Esse usuário já está na sua lista de amigos."}), 400

    current_friends.append(friend_username)
    conn.execute('UPDATE users SET friends = ? WHERE username = ?', 
                 (json.dumps(current_friends), current_user['username']))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"{friend_username} adicionado aos seus amigos."})

@app.route('/friends', methods=['DELETE'])
@token_required
def remove_friend(current_user):
    data = request.get_json()
    if not data or 'friend_username' not in data:
        return jsonify({"error": "O campo 'friend_username' é obrigatório."}), 400

    friend_username = data['friend_username'].strip().lower()
    current_friends = json.loads(current_user['friends'])

    if friend_username not in current_friends:
        return jsonify({"error": "Este usuário não está na sua lista de amigos."}), 404

    current_friends.remove(friend_username)
    conn = get_db_connection()
    conn.execute('UPDATE users SET friends = ? WHERE username = ?', 
                 (json.dumps(current_friends), current_user['username']))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"{friend_username} removido da sua lista de amigos."})

# --- Execução ---
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
