# -*- coding: utf-8 -*-

# -----------------------------------------------------------------------------
# API Syra - Versão 2.2.0: Comunicação Persistente e Segurança Aprimorada
# -----------------------------------------------------------------------------
# DESCRIÇÃO:
# Esta versão evolui a API para um sistema de comunicação mais robusto,
# implementando armazenamento persistente de mensagens, um fluxo de registro
# seguro e tolerante a falhas, e um mecanismo de rate limiting para
# proteção contra spam. A base está pronta para futuras expansões como
# chat em tempo real via WebSockets (FastAPI/Flask-SocketIO) e documentação
# automática (Swagger/OpenAPI).
#
# DEPENDÊNCIAS:
# Flask, Flask-Cors, pyotp, qrcode[pil], PyJWT, gunicorn
# > pip install Flask Flask-Cors pyotp "qrcode[pil]" PyJWT gunicorn
# -----------------------------------------------------------------------------
# PARA EXECUTAR EM DESENVOLVIMENTO (HTTP):
# > python seu_arquivo.py
#
# PARA EXECUTAR EM PRODUÇÃO (com Nginx/HTTPS na frente):
# > gunicorn --bind 127.0.0.1:5000 seu_arquivo:app
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
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Configuração da Aplicação ---
DB_NAME = "syra_v2_2.db"
APP_NAME = "Syra"

# --- CHAVES SECRETAS ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"

# --- Configuração de Rate Limiting ---
RATE_LIMIT_REQUESTS = 10  # Requisições
RATE_LIMIT_DURATION = 60  # Segundos
request_tracker = {} # Dicionário em memória para rastrear requisições: {ip: [timestamp1, ...]}

# --- Inicialização da API Flask e CORS ---
app = Flask(__name__)
CORS(app)

# --- Funções do Banco de Dados (SQLite) ---

def get_db_connection():
    """Estabelece uma conexão com o banco de dados SQLite."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa o banco de dados e cria todas as tabelas, se não existirem."""
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de Registros Pendentes (substitui o dict em memória)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_registrations (
                username TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Mensagens Reais
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT NOT NULL,
                receiver_username TEXT NOT NULL,
                content TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_username) REFERENCES users (username),
                FOREIGN KEY (receiver_username) REFERENCES users (username)
            )
        ''')

        # Tabela de Notificações (para eventos, não para conteúdo de mensagens)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                type TEXT NOT NULL, -- "new_message", "friend_request", "friend_accepted"
                content TEXT NOT NULL, -- Contexto (ex: nome do remetente)
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Logs de Atividade
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
        if 'conn' in locals() and conn:
            conn.close()

# --- Funções Auxiliares e Decorators ---

def log_action(action, username=None, details="", ip_address=None):
    """Registra uma ação no banco de dados de logs."""
    ip = ip_address or request.headers.get('X-Forwarded-For', request.remote_addr)
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO logs (action, username, details, ip_address) VALUES (?, ?, ?, ?)',
        (action, username, details, ip)
    )
    conn.commit()
    conn.close()

def rate_limited(f):
    """Decorator para limitar a taxa de requisições a um endpoint."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        now = time.time()
        
        # Filtra timestamps antigos
        if ip in request_tracker:
            request_tracker[ip] = [ts for ts in request_tracker[ip] if now - ts < RATE_LIMIT_DURATION]
        
        # Verifica o limite
        if ip in request_tracker and len(request_tracker.get(ip, [])) >= RATE_LIMIT_REQUESTS:
            return jsonify({"error": "Limite de requisições excedido. Tente novamente mais tarde."}), 429
            
        # Registra a requisição atual
        if ip not in request_tracker:
            request_tracker[ip] = []
        request_tracker[ip].append(now)

        return f(*args, **kwargs)
    return decorated

def token_required(f):
    """Decorator para proteger rotas que exigem um token JWT válido."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token de autenticação não fornecido"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            conn = get_db_connection()
            current_user = conn.execute('SELECT id, username, friends, created_at FROM users WHERE username = ?', (data['username'],)).fetchone()
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
    """Decorator para proteger rotas de administração."""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_token = request.headers.get('X-Admin-Token')
        if not admin_token or not secrets.compare_digest(admin_token, ADMIN_TOKEN):
            log_action("ADMIN_ACCESS_DENIED", details="Token inválido ou ausente")
            return jsonify({"error": "Acesso não autorizado."}), 403
        return f(*args, **kwargs)
    return decorated

# --- ROTAS DA API ---

# --- 0. Rota de Saúde da API ---
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "version": "2.2.0", "timestamp": datetime.utcnow().isoformat()})

# --- 1. Rotas de Autenticação (/auth) ---
@app.route('/auth/register', methods=['POST'])
@rate_limited
def register():
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({"error": "O campo 'username' é obrigatório"}), 400

    username = data['username'].strip().lower()
    conn = get_db_connection()
    if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        return jsonify({"error": "Este nome de usuário já está em uso"}), 409

    secret = pyotp.random_base32()
    # Salva o registro pendente no banco de dados
    conn.execute('INSERT OR REPLACE INTO pending_registrations (username, secret) VALUES (?, ?)', (username, secret))
    conn.commit()
    conn.close()
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    log_action("REGISTER_INITIATED", username)
    return jsonify({
        "message": "Escaneie o QR Code com seu app de autenticação e use /auth/verify para confirmar. O pedido expira em 15 minutos.",
        "secret_backup_key": secret,
        "qr_code_image": f"data:image/png;base64,{qr_code_b64}"
    })

@app.route('/auth/verify', methods=['POST'])
@rate_limited
def verify():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()
    
    conn = get_db_connection()
    pending_user = conn.execute('SELECT secret, created_at FROM pending_registrations WHERE username = ?', (username,)).fetchone()

    if not pending_user:
        conn.close()
        return jsonify({"error": "Registro não iniciado ou expirado. Use /auth/register primeiro."}), 404
        
    # Verifica se o registro expirou (15 minutos)
    expiration_time = datetime.strptime(pending_user['created_at'], '%Y-%m-%d %H:%M:%S') + timedelta(minutes=15)
    if datetime.utcnow() > expiration_time:
        conn.execute('DELETE FROM pending_registrations WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return jsonify({"error": "Pedido de registro expirado."}), 401

    secret = pending_user['secret']
    if pyotp.TOTP(secret).verify(totp_code):
        try:
            conn.execute('INSERT INTO users (username, secret) VALUES (?, ?)', (username, secret))
            conn.execute('DELETE FROM pending_registrations WHERE username = ?', (username,))
            conn.commit()
            log_action("REGISTER_COMPLETED", username)
            return jsonify({"status": "success", "message": "Usuário registrado com sucesso!"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Este nome de usuário já está em uso"}), 409
        finally:
            conn.close()
    else:
        conn.close()
        log_action("VERIFY_FAILED", username)
        return jsonify({"error": "Código de verificação inválido"}), 401

@app.route('/auth/login', methods=['POST'])
@rate_limited
def login():
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

# --- 2. Rotas de Perfil e Notificações (/me) ---
@app.route('/me/profile', methods=['GET'])
@token_required
def get_my_profile(current_user):
    current_user['friends'] = json.loads(current_user['friends'])
    return jsonify(current_user)

@app.route('/me/friends', methods=['GET'])
@token_required
def get_my_friends(current_user):
    return jsonify({"friends": json.loads(current_user['friends'])})

@app.route('/me/notifications', methods=['GET'])
@token_required
def get_my_notifications(current_user):
    conn = get_db_connection()
    notifications_cursor = conn.execute(
        'SELECT id, type, content, created_at FROM notifications WHERE username = ? AND is_read = 0 ORDER BY created_at DESC',
        (current_user['username'],)
    ).fetchall()
    
    notifications = [dict(row) for row in notifications_cursor]
    
    if notifications:
        # Marca as notificações como lidas
        notification_ids = tuple(n['id'] for n in notifications)
        placeholders = ','.join('?' for _ in notification_ids)
        conn.execute(f'UPDATE notifications SET is_read = 1 WHERE id IN ({placeholders})', notification_ids)
        conn.commit()
    
    conn.close()
    return jsonify(notifications)

# --- 3. Rotas de Interação com Usuários (/users) ---
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM users WHERE username != ?', (current_user['username'],)).fetchall()
    conn.close()
    return jsonify({"users": [row['username'] for row in users]})

@app.route('/users/<string:target_username>/friend-request', methods=['POST'])
@token_required
@rate_limited
def send_friend_request(current_user, target_username):
    target_username = target_username.lower()
    sender_username = current_user['username']
    
    # ... (lógica de verificação de amizade e pedido pendente) ...
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
        (target_username, 'friend_request', sender_username)
    )
    conn.commit()
    conn.close()
    
    log_action("FRIEND_REQUEST_SENT", sender_username, f"Para: {target_username}")
    return jsonify({"status": "success", "message": f"Pedido de amizade enviado para '{target_username}'."})

@app.route('/me/friends/respond', methods=['POST'])
@token_required
def respond_to_friend_request(current_user):
    # ... (código para aceitar/recusar amizade, igual à versão anterior) ...
    data = request.get_json()
    if not data or 'from_username' not in data or 'action' not in data:
        return jsonify({"error": "Campos 'from_username' e 'action' são obrigatórios."}), 400

    from_username = data['from_username'].lower()
    action = data['action'].lower()
    my_username = current_user['username']

    conn = get_db_connection()
    notification = conn.execute(
        'SELECT id FROM notifications WHERE username = ? AND type = ? AND content = ? AND is_read = 0',
        (my_username, 'friend_request', from_username)
    ).fetchone()

    if not notification:
        conn.close()
        return jsonify({"error": "Pedido de amizade não encontrado ou já respondido."}), 404

    conn.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification['id'],))

    if action == 'accept':
        my_friends = json.loads(current_user['friends'])
        my_friends.append(from_username)
        conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(my_friends), my_username))
        
        requester_user = conn.execute('SELECT friends FROM users WHERE username = ?', (from_username,)).fetchone()
        requester_friends = json.loads(requester_user['friends'])
        requester_friends.append(my_username)
        conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(requester_friends), from_username))

        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (from_username, 'friend_accepted', my_username)
        )
        
        log_action("FRIEND_REQUEST_ACCEPTED", my_username, f"De: {from_username}")
        message = f"Você e {from_username} agora são amigos."
    else: # action == 'decline'
        log_action("FRIEND_REQUEST_DECLINED", my_username, f"De: {from_username}")
        message = f"Pedido de amizade de {from_username} recusado."
    
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": message})


@app.route('/users/<string:friend_username>/friends', methods=['DELETE'])
@token_required
def remove_friend(current_user, friend_username):
    # ... (código para remover amizade, igual à versão anterior) ...
    friend_username = friend_username.lower()
    my_username = current_user['username']
    my_friends = json.loads(current_user['friends'])

    if friend_username not in my_friends:
        return jsonify({"error": "Este usuário não está na sua lista de amigos."}), 404

    conn = get_db_connection()
    my_friends.remove(friend_username)
    conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(my_friends), my_username))
    
    friend_user = conn.execute('SELECT friends FROM users WHERE username = ?', (friend_username,)).fetchone()
    if friend_user:
        their_friends = json.loads(friend_user['friends'])
        if my_username in their_friends:
            their_friends.remove(my_username)
            conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(their_friends), friend_username))

    conn.commit()
    conn.close()

    log_action("FRIEND_REMOVE", my_username, f"Amigo: {friend_username}")
    return jsonify({"status": "success", "message": f"Amizade com '{friend_username}' desfeita."})

# --- 4. Rotas de Mensagens (/messages) ---
@app.route('/messages/send', methods=['POST'])
@token_required
@rate_limited
def send_message(current_user):
    data = request.get_json()
    if not data or not data.get('to_username') or not data.get('content'):
        return jsonify({"error": "Campos 'to_username' e 'content' são obrigatórios"}), 400

    to_username = data['to_username'].strip().lower()
    message_content = data['content'].strip()
    sender_username = current_user['username']

    if to_username == sender_username:
        return jsonify({"error": "Você não pode enviar mensagens para si mesmo."}), 400

    conn = get_db_connection()
    
    if not conn.execute('SELECT id FROM users WHERE username = ?', (to_username,)).fetchone():
        conn.close()
        return jsonify({"error": f"Usuário '{to_username}' não encontrado."}), 404
    
    # 1. Salva a mensagem real no banco de dados
    conn.execute(
        'INSERT INTO messages (sender_username, receiver_username, content) VALUES (?, ?, ?)',
        (sender_username, to_username, message_content)
    )
    
    # 2. Envia uma notificação para o destinatário saber que há uma nova mensagem
    conn.execute(
        'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
        (to_username, 'new_message', sender_username) # O conteúdo é quem enviou
    )
    
    conn.commit()
    conn.close()

    log_action("MESSAGE_SENT", sender_username, f"Para: {to_username}")
    return jsonify({"status": "success", "message": "Mensagem enviada."}), 201

@app.route('/messages/<string:other_username>', methods=['GET'])
@token_required
def get_messages(current_user, other_username):
    """Busca o histórico de mensagens com outro usuário."""
    my_username = current_user['username']
    other_username = other_username.lower()

    conn = get_db_connection()
    
    # Busca todas as mensagens entre os dois usuários
    messages_cursor = conn.execute(
        '''
        SELECT id, sender_username, content, created_at, is_read FROM messages 
        WHERE (sender_username = ? AND receiver_username = ?) OR (sender_username = ? AND receiver_username = ?)
        ORDER BY created_at ASC
        ''',
        (my_username, other_username, other_username, my_username)
    ).fetchall()
    
    messages = [dict(row) for row in messages_cursor]
    
    # Marca as mensagens recebidas como lidas
    unread_message_ids = tuple(m['id'] for m in messages if m['sender_username'] == other_username and m['is_read'] == 0)
    if unread_message_ids:
        placeholders = ','.join('?' for _ in unread_message_ids)
        conn.execute(f'UPDATE messages SET is_read = 1 WHERE id IN ({placeholders})', unread_message_ids)
        conn.commit()
    
    conn.close()
    return jsonify(messages)

# --- 5. Rotas de Administração (/admin) ---
@app.route('/admin/logs', methods=['GET'])
@admin_required
def view_logs():
    limit = request.args.get('limit', 100, type=int)
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    log_action("ADMIN_VIEW_LOGS", "admin")
    return jsonify([dict(row) for row in logs])

@app.route('/admin/db/reset', methods=['POST'])
@admin_required
def admin_reset_db():
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
        init_db()
        log_action("ADMIN_DB_RESET", "admin")
        return jsonify({"status": "success", "message": "Banco de dados resetado e reinicializado."})
    except Exception as e:
        log_action("ADMIN_DB_RESET_FAILED", "admin", str(e))
        return jsonify({"error": f"Falha ao resetar o banco de dados: {e}"}), 500

# --- Bloco de Execução Principal ---
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
