#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rulix Admin Telegram Bot
Управление пользователями через Telegram
"""

import telebot
from telebot import types
import requests
import secrets
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════

# Получи токен у @BotFather в Telegram
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"  # ← ВСТАВЬ ТОКЕН БОТА

# Твой Telegram ID (узнай у @userinfobot)
ADMIN_IDS = [123456789]  # ← ВСТАВЬ СВОЙ ID

# API сервера
API_URL = "http://localhost:5000/api"  # ← ИЗМЕНИ НА СВОЙ СЕРВЕР
API_SECRET = "YOUR_SECRET_KEY_CHANGE_ME_123456789"  # ← ТОТ ЖЕ ЧТО В auth_server

# ═══════════════════════════════════════════════════════════════
# БОТ
# ═══════════════════════════════════════════════════════════════

bot = telebot.TeleBot(TELEGRAM_TOKEN)

def is_admin(user_id):
    """Проверка что пользователь админ"""
    return user_id in ADMIN_IDS

# ═══════════════════════════════════════════════════════════════
# КОМАНДЫ
# ═══════════════════════════════════════════════════════════════

@bot.message_handler(commands=['start'])
def start(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "❌ Доступ запрещен")
        return

    bot.reply_to(message, """
╔════════════════════════════════════════╗
║     RULIX ADMIN BOT                    ║
╚════════════════════════════════════════╝

Доступные команды:

📝 /create - Создать пользователя
👥 /list - Список пользователей
ℹ️ /help - Помощь

Powered by Rulix DLC
""")

@bot.message_handler(commands=['help'])
def help_command(message):
    if not is_admin(message.from_user.id):
        return

    bot.reply_to(message, """
📖 ПОМОЩЬ:

/create - Создать нового пользователя
Формат: /create username password дни

Примеры:
  /create player1 pass123 30
  /create testuser qwerty 7

/list - Показать всех пользователей

/help - Эта справка
""")

@bot.message_handler(commands=['create'])
def create_user(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "❌ Доступ запрещен")
        return

    try:
        # Парсим команду
        parts = message.text.split()

        if len(parts) < 3:
            bot.reply_to(message, """
❌ Неправильный формат!

Используй:
/create username password [дни]

Пример:
/create player1 pass123 30
""")
            return

        username = parts[1]
        password = parts[2]
        duration_days = int(parts[3]) if len(parts) > 3 else 30

        # Генерируем лицензию
        license_key = f"RULIX-{secrets.token_urlsafe(8).upper()}"

        # Отправляем на сервер
        bot.reply_to(message, f"⏳ Создаю пользователя {username}...")

        response = requests.post(
            f"{API_URL}/admin/create_user",
            json={
                "admin_token": API_SECRET,
                "username": username,
                "password": password,
                "duration_days": duration_days,
                "license_key": license_key
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if data.get('success'):
                user = data['user']
                expires = user['expires_at'][:10]

                result = f"""
✅ ПОЛЬЗОВАТЕЛЬ СОЗДАН!

👤 Username: `{username}`
🔑 Password: `{password}`
🎫 License: `{user['license_key']}`
📅 Expires: {expires}

Отправь эти данные клиенту!
"""
                bot.reply_to(message, result, parse_mode='Markdown')

                print(f"[BOT] User created: {username} by {message.from_user.username}")
            else:
                bot.reply_to(message, f"❌ Ошибка: {data.get('error')}")
        else:
            bot.reply_to(message, f"❌ Ошибка сервера: {response.status_code}")

    except ValueError:
        bot.reply_to(message, "❌ Дни должны быть числом!")
    except requests.exceptions.ConnectionError:
        bot.reply_to(message, "❌ Не могу подключиться к серверу!")
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка: {str(e)}")

@bot.message_handler(commands=['list'])
def list_users(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "❌ Доступ запрещен")
        return

    try:
        bot.reply_to(message, "⏳ Загружаю список пользователей...")

        response = requests.post(
            f"{API_URL}/admin/list_users",
            json={"admin_token": API_SECRET},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if data.get('success'):
                users = data['users']

                if not users:
                    bot.reply_to(message, "📭 Пользователей нет")
                    return

                result = "👥 СПИСОК ПОЛЬЗОВАТЕЛЕЙ:\n\n"

                for user in users:
                    status = "✅" if user['is_active'] else "❌"
                    expires = user['expires_at'][:10]

                    result += f"{status} **{user['username']}**\n"
                    result += f"   License: `{user['license_key']}`\n"
                    result += f"   Expires: {expires}\n\n"

                # Telegram ограничивает длину сообщения
                if len(result) > 4000:
                    result = result[:4000] + "\n\n... (список обрезан)"

                bot.reply_to(message, result, parse_mode='Markdown')
            else:
                bot.reply_to(message, f"❌ Ошибка: {data.get('error')}")
        else:
            bot.reply_to(message, f"❌ Ошибка сервера: {response.status_code}")

    except requests.exceptions.ConnectionError:
        bot.reply_to(message, "❌ Не могу подключиться к серверу!")
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка: {str(e)}")

# ═══════════════════════════════════════════════════════════════
# ЗАПУСК
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║           RULIX ADMIN TELEGRAM BOT                         ║
╚════════════════════════════════════════════════════════════╝
""")

    print(f"[INFO] Bot starting...")
    print(f"[INFO] Authorized admins: {ADMIN_IDS}")
    print(f"[INFO] API URL: {API_URL}")
    print()
    print("✅ Bot is running!")
    print("   Send /start in Telegram to begin")
    print()

    bot.infinity_polling()
