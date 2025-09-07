# -*- coding: utf-8 -*-
"""
API Syra - Versão 2.2.0 (pronta para deploy no Render)
Inclui:
- Inicialização automática do banco (criação de tabelas) ao importar o módulo
- Rotas de autenticação (register/verify/login) com TOTP + QR
- Persistência de mensagens, notificações e logs em SQLite
- Rate limiting por IP simples (memória por worker)
- Proteção por JWT e rota de administração com token
- Trivial rota raiz e handler de erros para respostas JSON

Para rodar em produção (Render):
- Build Command: pip install -r requirements.txt
- Start Command: gunicorn -w 4 -b 0.0.0.0:5000 api:app

NOTA: Gunicorn importa o módulo. Por isso init_db() é chamado no nível do módulo para garantir
que as tabelas existam antes dos workers atenderem requisições.
"""

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
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Configuração da Aplicação ---
DB_NAME = os.getenv("DATABASE_PATH", "syra_v2_2.db")  # pode ser sobrescrito via env
APP_NAME = os.getenv("APP_NAME", "Syra")

# --- CHAVES SECRETAS ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", secrets.token_hex(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# --- Configuração de Rate Limiting ---
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))  # Requisições
RATE_LIMIT_DURATION = int(os.getenv("RATE_LIMIT_DURATION", "60"))  # Segundos
request_tracker = {}  # Dicionário em memória para rastrear requisições por IP: {ip: [timestamp1, ...]}

# --- Inicialização do Flask ---
app = Flask(__name__)
CORS(app)

# Config logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("syra_api")

# --- Funções do Banco de Dados (SQLite) ---

def get_db_connection():
    """Estabelece uma conexão com o banco de dados SQLite."""
    # timeout aumenta a chance de contornar locks em ambientes concorrentes
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Inicializa o banco de dados e cria todas as tabelas, se não existirem."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        logger.info("Inicializando o banco de dados: %s", DB_NAME)

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

        # Tabela de Registros Pendentes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_registrations (
                username TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Mensagens
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

        # Tabela de Notificações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                type TEXT NOT NULL,
                content TEXT NOT NULL,
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

        # Índices úteis
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages (sender_username, receiver_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (username)')

        conn.commit()
        logger.info("Banco de dados '%s' pronto para uso.", DB_NAME)
        logger.info("🔑 Token de Admin (advice: armazene em env var ADMIN_TOKEN): %s", ADMIN_TOKEN)
    except sqlite3.Error as e:
        logger.exception("Erro ao inicializar o banco de dados: %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Chama init_db no import do módulo (importante para Gunicorn)
init_db()

# --- Funções Auxiliares e Decorators ---

def log_action(action, username=None, details="", ip_address=None):
    """Registra uma ação no banco de dados de logs."""
    try:
        # ip pode vir do cabeçalho X-Forwarded-For ou do request remoto
        ip = ip_address
        if ip is None:
            try:
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            except RuntimeError:
                ip = None

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO logs (action, username, details, ip_address) VALUES (?, ?, ?, ?)',
            (action, username, details, ip)
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Falha ao registrar log: %s %s", action, username)


def rate_limited(f):
    """Decorator para limitar a taxa de requisições a um endpoint (por IP)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        except RuntimeError:
            ip = 'unknown'

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
        except Exception:
            logger.exception("Erro ao validar token")
            return jsonify({"error": "Erro ao validar token."}), 401

        # converte Row para dict para isolamento
        user_dict = dict(current_user)
        return f(user_dict, *args, **kwargs)
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

@app.route('/')
def root():
    return jsonify({"message": f"{APP_NAME} API running", "version": "2.2.0"})

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
    try:
        if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            return jsonify({"error": "Este nome de usuário já está em uso"}), 409

        secret = pyotp.random_base32()
        # Salva o registro pendente no banco de dados
        conn.execute('INSERT OR REPLACE INTO pending_registrations (username, secret) VALUES (?, ?)', (username, secret))
        conn.commit()

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
    except Exception:
        logger.exception("Erro em /auth/register")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


@app.route('/auth/verify', methods=['POST'])
@rate_limited
def verify():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    try:
        pending_user = conn.execute('SELECT secret, created_at FROM pending_registrations WHERE username = ?', (username,)).fetchone()

        if not pending_user:
            return jsonify({"error": "Registro não iniciado ou expirado. Use /auth/register primeiro."}), 404

        # Tentativa de parse robusto para created_at
        created_at_raw = pending_user['created_at']
        try:
            expiration_time = datetime.strptime(created_at_raw, '%Y-%m-%d %H:%M:%S') + timedelta(minutes=15)
        except Exception:
            # fallback, sem segundos
            try:
                expiration_time = datetime.strptime(created_at_raw, '%Y-%m-%d %H:%M') + timedelta(minutes=15)
            except Exception:
                expiration_time = datetime.utcnow() + timedelta(minutes=15)

        if datetime.utcnow() > expiration_time:
            conn.execute('DELETE FROM pending_registrations WHERE username = ?', (username,))
            conn.commit()
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
        else:
            log_action("VERIFY_FAILED", username)
            return jsonify({"error": "Código de verificação inválido"}), 401
    except Exception:
        logger.exception("Erro em /auth/verify")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


@app.route('/auth/login', methods=['POST'])
@rate_limited
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT secret FROM users WHERE username = ?', (username,)).fetchone()

        if not user or not pyotp.TOTP(user['secret']).verify(totp_code):
            log_action("LOGIN_FAILED", username)
            return jsonify({"error": "Credenciais inválidas"}), 401

        token = jwt.encode({
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        log_action("LOGIN_SUCCESS", username)
        return jsonify({"status": "success", "token": token})
    except Exception:
        logger.exception("Erro em /auth/login")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


# --- 2. Rotas de Perfil e Notificações (/me) ---
@app.route('/me/profile', methods=['GET'])
@token_required
def get_my_profile(current_user):
    try:
        # current_user['friends'] já é string JSON
        current_user['friends'] = json.loads(current_user['friends']) if current_user.get('friends') else []
        return jsonify(current_user)
    except Exception:
        logger.exception("Erro em /me/profile")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/friends', methods=['GET'])
@token_required
def get_my_friends(current_user):
    try:
        return jsonify({"friends": json.loads(current_user['friends'])})
    except Exception:
        logger.exception("Erro em /me/friends")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/notifications', methods=['GET'])
@token_required
def get_my_notifications(current_user):
    try:
        conn = get_db_connection()
        notifications_cursor = conn.execute(
            'SELECT id, type, content, created_at FROM notifications WHERE username = ? AND is_read = 0 ORDER BY created_at DESC',
            (current_user['username'],)
        ).fetchall()

        notifications = [dict(row) for row in notifications_cursor]

        if notifications:
            notification_ids = tuple(n['id'] for n in notifications)
            placeholders = ','.join('?' for _ in notification_ids)
            conn.execute(f'UPDATE notifications SET is_read = 1 WHERE id IN ({placeholders})', notification_ids)
            conn.commit()

        conn.close()
        return jsonify(notifications)
    except Exception:
        logger.exception("Erro em /me/notifications")
        return jsonify({"error": "Erro interno"}), 500


# --- 3. Rotas de Interação com Usuários (/users) ---
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT username FROM users WHERE username != ?', (current_user['username'],)).fetchall()
        conn.close()
        return jsonify({"users": [row['username'] for row in users]})
    except Exception:
        logger.exception("Erro em /users")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/friend-request', methods=['POST'])
@token_required
@rate_limited
def send_friend_request(current_user, target_username):
    try:
        target_username = target_username.lower()
        sender_username = current_user['username']

        conn = get_db_connection()
        # checa existência do usuário alvo
        if not conn.execute('SELECT id FROM users WHERE username = ?', (target_username,)).fetchone():
            conn.close()
            return jsonify({"error": f"Usuário '{target_username}' não encontrado."}), 404

        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (target_username, 'friend_request', sender_username)
        )
        conn.commit()
        conn.close()

        log_action("FRIEND_REQUEST_SENT", sender_username, f"Para: {target_username}")
        return jsonify({"status": "success", "message": f"Pedido de amizade enviado para '{target_username}'."})
    except Exception:
        logger.exception("Erro em friend-request")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/friends/respond', methods=['POST'])
@token_required
def respond_to_friend_request(current_user):
    try:
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
            my_friends = json.loads(current_user['friends']) if current_user.get('friends') else []
            if from_username not in my_friends:
                my_friends.append(from_username)
                conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(my_friends), my_username))

            requester_user = conn.execute('SELECT friends FROM users WHERE username = ?', (from_username,)).fetchone()
            requester_friends = json.loads(requester_user['friends']) if requester_user and requester_user['friends'] else []
            if my_username not in requester_friends:
                requester_friends.append(my_username)
                conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(requester_friends), from_username))

            conn.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (from_username, 'friend_accepted', my_username)
            )

            log_action("FRIEND_REQUEST_ACCEPTED", my_username, f"De: {from_username}")
            message = f"Você e {from_username} agora são amigos."
        else:  # action == 'decline'
            log_action("FRIEND_REQUEST_DECLINED", my_username, f"De: {from_username}")
            message = f"Pedido de amizade de {from_username} recusado."

        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": message})
    except Exception:
        logger.exception("Erro em respond_to_friend_request")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:friend_username>/friends', methods=['DELETE'])
@token_required
def remove_friend(current_user, friend_username):
    try:
        friend_username = friend_username.lower()
        my_username = current_user['username']
        my_friends = json.loads(current_user['friends']) if current_user.get('friends') else []

        if friend_username not in my_friends:
            return jsonify({"error": "Este usuário não está na sua lista de amigos."}), 404

        conn = get_db_connection()
        my_friends.remove(friend_username)
        conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(my_friends), my_username))

        friend_user = conn.execute('SELECT friends FROM users WHERE username = ?', (friend_username,)).fetchone()
        if friend_user:
            their_friends = json.loads(friend_user['friends']) if friend_user['friends'] else []
            if my_username in their_friends:
                their_friends.remove(my_username)
                conn.execute('UPDATE users SET friends = ? WHERE username = ?', (json.dumps(their_friends), friend_username))

        conn.commit()
        conn.close()

        log_action("FRIEND_REMOVE", my_username, f"Amigo: {friend_username}")
        return jsonify({"status": "success", "message": f"Amizade com '{friend_username}' desfeita."})
    except Exception:
        logger.exception("Erro em remove_friend")
        return jsonify({"error": "Erro interno"}), 500


# --- 4. Rotas de Mensagens (/messages) ---
@app.route('/messages/send', methods=['POST'])
@token_required
@rate_limited
def send_message(current_user):
    try:
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

        conn.execute(
            'INSERT INTO messages (sender_username, receiver_username, content) VALUES (?, ?, ?)',
            (sender_username, to_username, message_content)
        )

        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (to_username, 'new_message', sender_username)
        )

        conn.commit()
        conn.close()

        log_action("MESSAGE_SENT", sender_username, f"Para: {to_username}")
        return jsonify({"status": "success", "message": "Mensagem enviada."}), 201
    except Exception:
        logger.exception("Erro em send_message")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/messages/<string:other_username>', methods=['GET'])
@token_required
def get_messages(current_user, other_username):
    try:
        my_username = current_user['username']
        other_username = other_username.lower()

        conn = get_db_connection()
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
    except Exception:
        logger.exception("Erro em get_messages")
        return jsonify({"error": "Erro interno"}), 500


# --- 5. Rotas de Administração (/admin) ---
@app.route('/admin/logs', methods=['GET'])
@admin_required
def view_logs():
    try:
        limit = request.args.get('limit', 100, type=int)
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        log_action("ADMIN_VIEW_LOGS", "admin")
        return jsonify([dict(row) for row in logs])
    except Exception:
        logger.exception("Erro em view_logs")
        return jsonify({"error": "Erro interno"}), 500


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
        logger.exception("Erro em admin_reset_db: %s", e)
        log_action("ADMIN_DB_RESET_FAILED", "admin", str(e))
        return jsonify({"error": f"Falha ao resetar o banco de dados: {e}"}), 500


# --- Handlers de erro gerais ---
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Rota não encontrada"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error: %s", e)
    return jsonify({"error": "Erro interno do servidor"}), 500


# --- Bloco de Execução Principal (apenas para run local) ---
if __name__ == '__main__':
    # porta para desenvolvimento — Render/Gunicorn define PORT e não executa esse bloco
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
