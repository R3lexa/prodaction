#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rulix Auth API Server
Secure REST API for authentication
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
# СЕКРЕТНЫЙ КЛЮЧ ДЛЯ ПОДПИСИ ЗАПРОСОВ (МЕНЯЙ!)
# ═══════════════════════════════════════════════════════════════
API_SECRET = "YOUR_SECRET_KEY_CHANGE_ME_123456789"  # ← МЕНЯЙ ЭТО!
DB_PATH = Path("server_data/rulix_auth.db")

# ═══════════════════════════════════════════════════════════════
# ЗАЩИТА ОТ БРУТФОРСА
# ═══════════════════════════════════════════════════════════════
failed_attempts = {}  # IP -> (count, last_attempt_time)
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 минут

def check_rate_limit(ip):
    """Проверка лимита попыток"""
    if ip in failed_attempts:
        count, last_time = failed_attempts[ip]
        if time.time() - last_time < LOCKOUT_TIME and count >= MAX_ATTEMPTS:
            return False, f"Too many attempts. Try again in {int(LOCKOUT_TIME - (time.time() - last_time))} seconds"
    return True, None

def record_failed_attempt(ip):
    """Запись неудачной попытки"""
    if ip in failed_attempts:
        count, _ = failed_attempts[ip]
        failed_attempts[ip] = (count + 1, time.time())
    else:
        failed_attempts[ip] = (1, time.time())

def clear_failed_attempts(ip):
    """Очистка счетчика после успеха"""
    if ip in failed_attempts:
        del failed_attempts[ip]

# ═══════════════════════════════════════════════════════════════
# ПРОВЕРКА ПОДПИСИ ЗАПРОСА
# ═══════════════════════════════════════════════════════════════
def verify_signature(data, signature):
    """Проверяет HMAC подпись запроса"""
    expected = hmac.new(
        API_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# ═══════════════════════════════════════════════════════════════
# БАЗА ДАННЫХ
# ═══════════════════════════════════════════════════════════════
def get_db():
    """Подключение к БД"""
    DB_PATH.parent.mkdir(exist_ok=True)
    return sqlite3.connect(str(DB_PATH))

def hash_password(password):
    """Хэширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health_check():
    """Проверка работоспособности сервера"""
    return jsonify({
        'status': 'online',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Авторизация пользователя

    POST /api/auth/login
    {
        "username": "...",
        "password": "...",
        "hwid": "...",
        "signature": "HMAC-SHA256(...)"
    }
    """
    try:
        # Получаем IP клиента
        client_ip = request.remote_addr

        # Проверяем rate limit
        allowed, error_msg = check_rate_limit(client_ip)
        if not allowed:
            return jsonify({
                'success': False,
                'error': error_msg
            }), 429

        data = request.get_json()

        # Валидация
        if not all(k in data for k in ['username', 'password', 'hwid', 'signature']):
            record_failed_attempt(client_ip)
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        username = data['username']
        password = data['password']
        hwid = data['hwid']
        signature = data['signature']

        # Проверяем подпись
        payload = f"{username}:{password}:{hwid}"
        if not verify_signature(payload, signature):
            record_failed_attempt(client_ip)

            # Логируем подозрительную активность
            print(f"[SECURITY] Invalid signature from {client_ip}")
            print(f"[SECURITY] Username: {username}, HWID: {hwid}")

            return jsonify({
                'success': False,
                'error': 'Invalid signature'
            }), 403

        # Подключаемся к БД
        conn = get_db()
        cursor = conn.cursor()

        password_hash = hash_password(password)

        # Ищем пользователя
        cursor.execute("""
            SELECT id, hwid, expires_at, license_key, is_active
            FROM users
            WHERE username = ? AND password_hash = ?
        """, (username, password_hash))

        user = cursor.fetchone()

        if not user:
            record_failed_attempt(client_ip)

            # Логируем попытку
            cursor.execute("""
                INSERT INTO login_attempts (username, success, hwid, ip_address)
                VALUES (?, 0, ?, ?)
            """, (username, hwid, client_ip))
            conn.commit()
            conn.close()

            return jsonify({
                'success': False,
                'error': 'Invalid credentials'
            }), 401

        user_id, stored_hwid, expires_at, license_key, is_active = user

        # Проверяем активность
        if not is_active:
            record_failed_attempt(client_ip)
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Account disabled'
            }), 403

        # Проверяем срок
        expires = datetime.fromisoformat(expires_at)
        if datetime.now() > expires:
            record_failed_attempt(client_ip)
            conn.close()
            return jsonify({
                'success': False,
                'error': 'License expired'
            }), 403

        # HWID проверка
        if stored_hwid and stored_hwid != hwid:
            record_failed_attempt(client_ip)

            # Логируем подозрительную активность
            print(f"[SECURITY] HWID mismatch for user {username}")
            print(f"[SECURITY] Expected: {stored_hwid}, Got: {hwid}")

            conn.close()
            return jsonify({
                'success': False,
                'error': 'HWID mismatch'
            }), 403

        # Привязываем HWID если нужно
        if not stored_hwid:
            cursor.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, user_id))
            conn.commit()

        # Логируем успешный вход
        cursor.execute("""
            INSERT INTO login_attempts (username, success, hwid, ip_address)
            VALUES (?, 1, ?, ?)
        """, (username, hwid, client_ip))
        conn.commit()
        conn.close()

        # Очищаем счетчик неудачных попыток
        clear_failed_attempts(client_ip)

        # Генерируем session token
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

        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_session():
    """
    Проверка session token

    POST /api/auth/verify
    {
        "session_token": "...",
        "hwid": "...",
        "signature": "..."
    }
    """
    # TODO: Реализовать проверку сессии
    return jsonify({
        'success': True,
        'valid': True
    })

# ═══════════════════════════════════════════════════════════════
# ЗАПУСК СЕРВЕРА
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║              RULIX AUTH API SERVER                         ║
║              Secure Authentication System                  ║
╚════════════════════════════════════════════════════════════╝
    """)

    print("[INFO] Starting server...")
    print(f"[INFO] Database: {DB_PATH}")
    print(f"[INFO] API Secret: {'*' * len(API_SECRET)}")
    print()
    print("[SECURITY] Rate limiting enabled")
    print("[SECURITY] HMAC signature verification enabled")
    print()
    print("="*60)
    print()

    # Для разработки: debug=True, для продакшена: debug=False
    # Для продакшена используй Gunicorn или uWSGI!

    # DEVELOPMENT:
    app.run(host='0.0.0.0', port=5000, debug=True)

    # PRODUCTION (example):
    # gunicorn -w 4 -b 0.0.0.0:5000 auth_server:app
