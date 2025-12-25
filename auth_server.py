#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rulix Auth API Server
With auto database initialization
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import json
import time

app = Flask(__name__)
CORS(app)

# ═══════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════
API_SECRET = "G_SECRET_KEY_CHANGE_ME_123456789"  # ← МЕНЯЙ ЭТО!
DB_PATH = Path("server_data/rulix_auth.db")

# ═══════════════════════════════════════════════════════════════
# АВТОМАТИЧЕСКОЕ СОЗДАНИЕ БД
# ═══════════════════════════════════════════════════════════════

def init_database():
    """Создание БД и таблиц если их нет"""
    print("[DB] Checking database...")

    DB_PATH.parent.mkdir(exist_ok=True)

    if not DB_PATH.exists():
        print("[DB] Database not found, creating new...")

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # Создаем таблицу пользователей
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_key TEXT NOT NULL,
            hwid TEXT,
            expires_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Создаем таблицу попыток входа
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            hwid TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Проверяем есть ли пользователи
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        print("[DB] No users found, creating default admin...")

        # Создаем дефолтного админа
        admin_password = secrets.token_urlsafe(16)
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        expires_at = (datetime.now() + timedelta(days=365)).isoformat()

        cursor.execute("""
            INSERT INTO users (username, password_hash, license_key, expires_at)
            VALUES (?, ?, ?, ?)
        """, ("admin", password_hash, "ADMIN-KEY", expires_at))

        conn.commit()

        print("[DB] ═══════════════════════════════════════════════════")
        print("[DB] ✅ DEFAULT ADMIN CREATED:")
        print(f"[DB]    Username: admin")
        print(f"[DB]    Password: {admin_password}")
        print("[DB]    License: ADMIN-KEY")
        print("[DB]    Expires: {0}".format(expires_at[:10]))
        print("[DB] ═══════════════════════════════════════════════════")
        print("[DB] ⚠️  СОХРАНИ ЭТОТ ПАРОЛЬ!")
        print("[DB] ═══════════════════════════════════════════════════")

    conn.close()
    print("[DB] ✅ Database ready")

# ═══════════════════════════════════════════════════════════════
# ЗАЩИТА ОТ БРУТФОРСА
# ═══════════════════════════════════════════════════════════════
failed_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300

def check_rate_limit(ip):
    if ip in failed_attempts:
        count, last_time = failed_attempts[ip]
        if time.time() - last_time < LOCKOUT_TIME and count >= MAX_ATTEMPTS:
            return False, f"Too many attempts. Try again in {int(LOCKOUT_TIME - (time.time() - last_time))} seconds"
    return True, None

def record_failed_attempt(ip):
    if ip in failed_attempts:
        count, _ = failed_attempts[ip]
        failed_attempts[ip] = (count + 1, time.time())
    else:
        failed_attempts[ip] = (1, time.time())

def clear_failed_attempts(ip):
    if ip in failed_attempts:
        del failed_attempts[ip]

# ═══════════════════════════════════════════════════════════════
# УТИЛИТЫ
# ═══════════════════════════════════════════════════════════════

def verify_signature(data, signature):
    expected = hmac.new(
        API_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

def get_db():
    return sqlite3.connect(str(DB_PATH))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'online',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        client_ip = request.remote_addr

        allowed, error_msg = check_rate_limit(client_ip)
        if not allowed:
            return jsonify({'success': False, 'error': error_msg}), 429

        data = request.get_json()

        if not all(k in data for k in ['username', 'password', 'hwid', 'signature']):
            record_failed_attempt(client_ip)
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        username = data['username']
        password = data['password']
        hwid = data['hwid']
        signature = data['signature']

        payload = f"{username}:{password}:{hwid}"
        if not verify_signature(payload, signature):
            record_failed_attempt(client_ip)
            print(f"[SECURITY] Invalid signature from {client_ip}")
            return jsonify({'success': False, 'error': 'Invalid signature'}), 403

        conn = get_db()
        cursor = conn.cursor()

        password_hash = hash_password(password)

        cursor.execute("""
            SELECT id, hwid, expires_at, license_key, is_active
            FROM users
            WHERE username = ? AND password_hash = ?
        """, (username, password_hash))

        user = cursor.fetchone()

        if not user:
            record_failed_attempt(client_ip)
            cursor.execute("""
                INSERT INTO login_attempts (username, success, hwid, ip_address)
                VALUES (?, 0, ?, ?)
            """, (username, hwid, client_ip))
            conn.commit()
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        user_id, stored_hwid, expires_at, license_key, is_active = user

        if not is_active:
            record_failed_attempt(client_ip)
            conn.close()
            return jsonify({'success': False, 'error': 'Account disabled'}), 403

        expires = datetime.fromisoformat(expires_at)
        if datetime.now() > expires:
            record_failed_attempt(client_ip)
            conn.close()
            return jsonify({'success': False, 'error': 'License expired'}), 403

        if stored_hwid and stored_hwid != hwid:
            record_failed_attempt(client_ip)
            print(f"[SECURITY] HWID mismatch for {username}")
            conn.close()
            return jsonify({'success': False, 'error': 'HWID mismatch'}), 403

        if not stored_hwid:
            cursor.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, user_id))
            conn.commit()

        cursor.execute("""
            INSERT INTO login_attempts (username, success, hwid, ip_address)
            VALUES (?, 1, ?, ?)
        """, (username, hwid, client_ip))
        conn.commit()
        conn.close()

        clear_failed_attempts(client_ip)

        session_token = secrets.token_urlsafe(32)

        return jsonify({
            'success': True,
            'user': {
                'user_id': user_id,
                'username': username,
                'license_key': license_key,
                'expires_at': expires_at,
                'session_token': session_token
            }
        }), 200

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ═══════════════════════════════════════════════════════════════
# ADMIN API (ДЛЯ TELEGRAM БОТА)
# ═══════════════════════════════════════════════════════════════

@app.route('/api/admin/create_user', methods=['POST'])
def create_user():
    """Создание нового пользователя (для Telegram бота)"""
    try:
        data = request.get_json()

        # Проверка admin токена
        admin_token = data.get('admin_token')
        if admin_token != API_SECRET:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        username = data.get('username')
        password = data.get('password')
        duration_days = data.get('duration_days', 30)
        license_key = data.get('license_key', secrets.token_urlsafe(12))

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Проверяем что username не занят
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Username already exists'}), 400

        password_hash = hash_password(password)
        expires_at = (datetime.now() + timedelta(days=duration_days)).isoformat()

        cursor.execute("""
            INSERT INTO users (username, password_hash, license_key, expires_at)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, license_key, expires_at))

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        print(f"[ADMIN] New user created: {username} (ID: {user_id})")

        return jsonify({
            'success': True,
            'user': {
                'id': user_id,
                'username': username,
                'license_key': license_key,
                'expires_at': expires_at
            }
        }), 200

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/list_users', methods=['POST'])
def list_users():
    """Список всех пользователей"""
    try:
        data = request.get_json()

        admin_token = data.get('admin_token')
        if admin_token != API_SECRET:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, license_key, expires_at, is_active, created_at
            FROM users
            ORDER BY created_at DESC
        """)

        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'license_key': row[2],
                'expires_at': row[3],
                'is_active': bool(row[4]),
                'created_at': row[5]
            })

        conn.close()

        return jsonify({'success': True, 'users': users}), 200

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# ЗАПУСК
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║              RULIX AUTH API SERVER v2.1                    ║
║              With Auto Database Init                       ║
╚════════════════════════════════════════════════════════════╝
    """)

    # Инициализация БД
    init_database()

    print(f"[INFO] Database: {DB_PATH}")
    print(f"[INFO] API Secret: {'*' * len(API_SECRET)}")
    print()
    print("[SECURITY] Rate limiting enabled")
    print("[SECURITY] HMAC signature verification enabled")
    print("[ADMIN] Admin API enabled for Telegram bot")
    print()
    print("="*60)
    print()

    app.run(host='0.0.0.0', port=5000, debug=False)
