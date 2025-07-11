# -*- coding: utf-8 -*-

# -----------------------------------------------------------------------------
# API Syra - Versão 2.0: RESTful, P2P-Ready e com Gamificação
# -----------------------------------------------------------------------------
# DESCRIÇÃO:
# Esta versão evolui a API para uma estrutura RESTful mais robusta, adicionando
# funcionalidades de interação entre usuários como mensagens, sistema de XP,
# conquistas, notificações, logs de auditoria e rotas de administração.
#
# DEPENDÊNCIAS:
# Flask, Flask-Cors, pyotp, qrcode[pil], PyJWT
# > pip install Flask Flask-Cors pyotp "qrcode[pil]" PyJWT
# -----------------------------------------------------------------------------
# PARA EXECUTAR:
# > python seu_arquivo.py
#
# COMO USAR AS ROTAS DE ADMIN:
# Envie as requisições com o cabeçalho:
# X-Admin-Token: seu-token-secreto-de-admin
# -----------------------------------------------------------------------------

import sqlite3
import pyotp
import qrcode
import io
import base64
import jwt
import json
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Configuração da Aplicação ---
DB_NAME = "syra_v2.db"
APP_NAME = "Syra"

# CHAVES SECRETAS: Em produção, carregue-as de variáveis de ambiente.
# Ex: JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
JWT_SECRET_KEY = secrets.token_hex(32)
ADMIN_TOKEN = secrets.token_hex(32) # Token para acessar rotas de admin
JWT_ALGORITHM = "HS256"

# Configurações de Gamificação
XP_PER_MESSAGE = 5
ACHIEVEMENT_MILESTONES = {
    100: "Iniciado",
    500: "Comunicador",
    1000: "Veterano",
    2500: "Mestre da Rede"
}

# --- Inicialização da API Flask e CORS ---
app = Flask(__name__)
CORS(app)

# Dicionário em memória para registros pendentes
pending_registrations = {}

# --- Funções do Banco de Dados (SQLite) ---

def get_db_connection():
    """Estabelece uma conexão com o banco de dados SQLite."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa o banco de dados e cria todas as tabelas necessárias."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("Inicializando o banco de dados...")

        # Tabela de Usuários (users)
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

        # Tabela de Nós Temporários (db_temp)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS db_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                node TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')
        
        # Tabela de Notificações (notifications)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                type TEXT NOT NULL, -- "message", "friend_request", "achievement"
                content TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Logs de Atividade (logs)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                username TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        print(f"Banco de dados '{DB_NAME}' pronto para uso.")
        print(f"🔑 Seu Token de Admin é: {ADMIN_TOKEN}")
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")
    finally:
        if conn:
            conn.close()

# --- Funções Auxiliares (Logs, Conquistas) ---

def log_action(action, username=None, details="", ip_address=None):
    """Registra uma ação no banco de dados de logs."""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO logs (action, username, details, ip_address) VALUES (?, ?, ?, ?)',
        (action, username, details, ip_address or request.remote_addr)
    )
    conn.commit()
    conn.close()

def check_and_grant_achievements(conn, user):
    """Verifica e concede novas conquistas com base no XP."""
    current_achievements = json.loads(user['achievements'])
    new_achievements_granted = []

    for xp_milestone, name in ACHIEVEMENT_MILESTONES.items():
        if user['exp'] >= xp_milestone and name not in current_achievements:
            current_achievements.append(name)
            new_achievements_granted.append(name)
            # Cria uma notificação para o usuário
            conn.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (user['username'], 'achievement', f"Você desbloqueou a conquista: '{name}'!")
            )
    
    if new_achievements_granted:
        conn.execute(
            'UPDATE users SET achievements = ? WHERE username = ?',
            (json.dumps(current_achievements), user['username'])
        )
        log_action("ACHIEVEMENT_UNLOCKED", user['username'], f"Conquistas: {', '.join(new_achievements_granted)}")
        return True
    return False

# --- Decorators de Autenticação ---

def token_required(f):
    """Decorator para proteger rotas que exigem um token JWT válido."""
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
            return jsonify({"error": "Token expirado. Por favor, faça login novamente."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido."}), 401
        
        return f(dict(current_user), *args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator para proteger rotas de administração com um token estático."""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_token = request.headers.get('X-Admin-Token')
        if not admin_token or admin_token != ADMIN_TOKEN:
            log_action("ADMIN_ACCESS_DENIED", details="Token inválido ou ausente", ip_address=request.remote_addr)
            return jsonify({"error": "Acesso não autorizado."}), 403
        return f(*args, **kwargs)
    return decorated


# --- ROTAS DA API ---

# --- 0. Rota de Saúde da API ---
@app.route('/health', methods=['GET'])
def health_check():
    """Verifica se a API está online."""
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

# --- 1. Rotas de Autenticação (/auth) ---
@app.route('/auth/register', methods=['POST'])
def register():
    """Passo 1 do Registro: Gera segredo e QR Code."""
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({"error": "O campo 'username' é obrigatório"}), 400

    username = data['username'].strip().lower()
    conn = get_db_connection()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        return jsonify({"error": "Este nome de usuário já está em uso"}), 409
    conn.close()

    secret = pyotp.random_base32()
    pending_registrations[username] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
    
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    log_action("REGISTER_INITIATED", username)
    return jsonify({
        "message": "Escaneie o QR Code e use a rota /auth/verify para confirmar.",
        "secret_backup_key": secret,
        "qr_code_image": f"data:image/png;base64,{qr_code_b64}"
    })

@app.route('/auth/verify', methods=['POST'])
def verify():
    """Passo 2 do Registro: Verifica o código TOTP e salva o usuário."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()
    
    if username not in pending_registrations:
        return jsonify({"error": "Registro não iniciado ou expirado. Use /auth/register primeiro."}), 404

    secret = pending_registrations[username]
    if pyotp.TOTP(secret).verify(totp_code):
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, secret) VALUES (?, ?)', (username, secret))
            conn.commit()
            del pending_registrations[username]
            log_action("REGISTER_COMPLETED", username)
            return jsonify({"status": "success", "message": "Usuário registrado com sucesso!"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Este nome de usuário já está em uso"}), 409
        finally:
            conn.close()
    else:
        log_action("VERIFY_FAILED", username)
        return jsonify({"error": "Código de verificação inválido"}), 401

@app.route('/auth/login', methods=['POST'])
def login():
    """Realiza o login e retorna um token JWT."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    user = conn.execute('SELECT secret FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not user or not pyotp.TOTP(user['secret']).verify(totp_code):
        log_action("LOGIN_FAILED", username)
        return jsonify({"error": "Credenciais inválidas"}), 401

    token = jwt.encode({
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    log_action("LOGIN_SUCCESS", username)
    return jsonify({"status": "success", "token": token})

# --- 2. Rotas do Usuário Logado (/me) ---
@app.route('/me/profile', methods=['GET'])
@token_required
def get_my_profile(current_user):
    """Retorna o perfil do usuário autenticado."""
    del current_user['secret']
    del current_user['id']
    current_user['friends'] = json.loads(current_user['friends'])
    current_user['achievements'] = json.loads(current_user['achievements'])
    return jsonify(current_user)

@app.route('/me/friends', methods=['GET'])
@token_required
def get_my_friends(current_user):
    """Retorna a lista de amigos do usuário autenticado."""
    return jsonify({"friends": json.loads(current_user['friends'])})

@app.route('/me/notifications', methods=['GET'])
@token_required
def get_my_notifications(current_user):
    """Busca e consome as notificações não lidas do usuário."""
    conn = get_db_connection()
    notifications_cursor = conn.execute(
        'SELECT type, content, created_at FROM notifications WHERE username = ? AND is_read = 0 ORDER BY created_at DESC',
        (current_user['username'],)
    ).fetchall()
    
    # Marca as notificações como lidas
    conn.execute('UPDATE notifications SET is_read = 1 WHERE username = ?', (current_user['username'],))
    conn.commit()
    conn.close()

    notifications = [dict(row) for row in notifications_cursor]
    return jsonify(notifications)

# --- 3. Rotas de Interação com Usuários (/users) ---
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    """Retorna uma lista de todos os usernames registrados."""
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM users WHERE username != ?', (current_user['username'],)).fetchall()
    conn.close()
    return jsonify({"users": [row['username'] for row in users]})

@app.route('/users/search', methods=['GET'])
@token_required
def search_users(current_user):
    """Busca usuários por parte do nome."""
    query = request.args.get('q', '').strip().lower()
    if len(query) < 2:
        return jsonify({"error": "A busca requer no mínimo 2 caracteres."}), 400

    conn = get_db_connection()
    results = conn.execute(
        "SELECT username FROM users WHERE username LIKE ? AND username != ?",
        (f"%{query}%", current_user['username'])
    ).fetchall()
    conn.close()
    return jsonify({"results": [row['username'] for row in results]})

@app.route('/users/<string:friend_username>/friends', methods=['POST'])
@token_required
def add_friend(current_user, friend_username):
    """Adiciona um amigo e envia uma notificação."""
    friend_username = friend_username.lower()
    if friend_username == current_user['username']:
        return jsonify({"error": "Você não pode adicionar a si mesmo."}), 400

    conn = get_db_connection()
    friend_exists = conn.execute('SELECT id FROM users WHERE username = ?', (friend_username,)).fetchone()
    if not friend_exists:
        conn.close()
        return jsonify({"error": "Usuário amigo não encontrado."}), 404

    my_friends = json.loads(current_user['friends'])
    if friend_username in my_friends:
        conn.close()
        return jsonify({"error": "Este usuário já é seu amigo."}), 409

    my_friends.append(friend_username)
    conn.execute('UPDATE users SET friends = ? WHERE id = ?', (json.dumps(my_friends), current_user['id']))
    conn.execute(
        'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
        (friend_username, 'friend_request', f"{current_user['username']} adicionou você como amigo.")
    )
    conn.commit()
    conn.close()

    log_action("FRIEND_ADD", current_user['username'], f"Amigo: {friend_username}")
    return jsonify({"status": "success", "message": f"{friend_username} adicionado com sucesso."}), 200

@app.route('/users/<string:friend_username>/friends', methods=['DELETE'])
@token_required
def remove_friend(current_user, friend_username):
    """Remove um amigo da lista."""
    friend_username = friend_username.lower()
    my_friends = json.loads(current_user['friends'])

    if friend_username not in my_friends:
        return jsonify({"error": "Este usuário não está na sua lista de amigos."}), 404

    my_friends.remove(friend_username)
    conn = get_db_connection()
    conn.execute('UPDATE users SET friends = ? WHERE id = ?', (json.dumps(my_friends), current_user['id']))
    conn.commit()
    conn.close()

    log_action("FRIEND_REMOVE", current_user['username'], f"Amigo: {friend_username}")
    return jsonify({"status": "success", "message": f"{friend_username} removido da lista de amigos."}), 200

# --- 4. Rotas de Mensagens (/messages) ---
@app.route('/messages/send', methods=['POST'])
@token_required
def send_message(current_user):
    """Envia uma mensagem para outro usuário, concede XP e cria notificação."""
    data = request.get_json()
    if not data or not data.get('to_username') or not data.get('message'):
        return jsonify({"error": "Campos 'to_username' e 'message' são obrigatórios"}), 400

    to_username = data['to_username'].strip().lower()
    message_content = data['message'].strip()

    if to_username == current_user['username']:
        return jsonify({"error": "Você não pode enviar mensagens para si mesmo."}), 400

    conn = get_db_connection()
    recipient = conn.execute('SELECT id FROM users WHERE username = ?', (to_username,)).fetchone()
    if not recipient:
        conn.close()
        return jsonify({"error": f"Usuário '{to_username}' não encontrado."}), 404
    
    # 1. Adiciona XP ao remetente
    new_exp = current_user['exp'] + XP_PER_MESSAGE
    conn.execute('UPDATE users SET exp = ? WHERE id = ?', (new_exp, current_user['id']))
    
    # 2. Verifica se o remetente ganhou conquistas
    user_for_achievements = dict(current_user)
    user_for_achievements['exp'] = new_exp # Simula o novo XP para a função
    check_and_grant_achievements(conn, user_for_achievements)
    
    # 3. Cria a notificação para o destinatário
    conn.execute(
        'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
        (to_username, 'message', f"Nova mensagem de {current_user['username']}: '{message_content[:50]}...'")
    )
    
    conn.commit()
    conn.close()

    log_action("MESSAGE_SENT", current_user['username'], f"Para: {to_username}")
    return jsonify({"status": "success", "message": "Mensagem enviada.", "xp_gained": XP_PER_MESSAGE})

# --- 5. Rotas de Nós Temporários (/me/nodes) ---
@app.route('/me/nodes', methods=['POST'])
@token_required
def add_temp_node(current_user):
    """Adiciona um 'nó' temporário para o usuário autenticado."""
    data = request.get_json()
    if not data or not data.get('node'):
        return jsonify({"error": "O campo 'node' é obrigatório"}), 400
    
    conn = get_db_connection()
    conn.execute('INSERT INTO db_temp (username, node) VALUES (?, ?)', (current_user['username'], data['node']))
    conn.commit()
    conn.close()

    log_action("NODE_ADD", current_user['username'])
    return jsonify({"status": "success", "message": "Nó adicionado."}), 201

@app.route('/me/nodes', methods=['GET'])
@token_required
def get_my_temp_nodes(current_user):
    """Lista os 'nós' temporários do usuário autenticado."""
    conn = get_db_connection()
    nodes_cursor = conn.execute('SELECT id, node, created_at FROM db_temp WHERE username = ?', (current_user['username'],)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in nodes_cursor])

@app.route('/me/nodes/<int:node_id>', methods=['DELETE'])
@token_required
def delete_temp_node(current_user, node_id):
    """Deleta um 'nó' específico do usuário autenticado."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM db_temp WHERE id = ? AND username = ?', (node_id, current_user['username']))
    conn.commit()
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "Nó não encontrado ou não pertence a este usuário."}), 404
        
    conn.close()
    log_action("NODE_DELETE", current_user['username'], f"Node ID: {node_id}")
    return jsonify({"status": "success", "message": f"Nó {node_id} deletado."})

# --- 6. Rotas de Administração (/admin) ---
@app.route('/admin/logs', methods=['GET'])
@admin_required
def view_logs():
    """Exibe os últimos 100 logs de atividade."""
    limit = request.args.get('limit', 100, type=int)
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    log_action("ADMIN_VIEW_LOGS", "admin")
    return jsonify([dict(row) for row in logs])

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    """Exibe todos os dados de todos os usuários (rota sensível)."""
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, friends, exp, achievements, created_at FROM users').fetchall()
    conn.close()
    log_action("ADMIN_VIEW_USERS", "admin")
    return jsonify([dict(row) for row in users])

@app.route('/admin/db/reset', methods=['POST'])
@admin_required
def admin_reset_db():
    """Apaga e recria o banco de dados. AÇÃO DESTRUTIVA."""
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
        init_db()
        log_action("ADMIN_DB_RESET", "admin", "Banco de dados resetado com sucesso.")
        return jsonify({"status": "success", "message": "Banco de dados resetado e reinicializado."})
    except Exception as e:
        return jsonify({"error": f"Falha ao resetar o banco de dados: {e}"}), 500


# --- Bloco de Execução Principal ---
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
