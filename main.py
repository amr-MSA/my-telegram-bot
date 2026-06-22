#!/usr/bin/env python3
"""
Anti-Spam Telegram Bot for Small Groups (<=100 members)
Optimized for Render Free Tier (512MB RAM) with Webhook
Uses Supabase PostgreSQL for persistent storage
"""

import os
import re
import logging
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, List

from flask import Flask, request, jsonify
from dotenv import load_dotenv
import psycopg2
from telegram import Update, ChatMember
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ChatMemberHandler,
    ContextTypes, filters
)

# ============================================================
# CONFIGURATION & LOGGING
# ============================================================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")
OWNER_ID_STR = os.getenv("OWNER_ID")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
PORT = int(os.getenv("PORT", "10000"))

if not BOT_TOKEN:
    logger.critical("BOT_TOKEN not set!")
    raise SystemExit(1)
if not WEBHOOK_SECRET:
    logger.critical("WEBHOOK_SECRET not set!")
    raise SystemExit(1)
if not SUPABASE_DB_URL:
    logger.critical("SUPABASE_DB_URL not set!")
    raise SystemExit(1)
if not OWNER_ID_STR:
    logger.critical("OWNER_ID not set!")
    raise SystemExit(1)

OWNER_ID = int(OWNER_ID_STR)

# ============================================================
# DATABASE SETUP
# ============================================================

def get_db_connection():
    return psycopg2.connect(SUPABASE_DB_URL, sslmode="require")


def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            user_id BIGINT NOT NULL,
            chat_id BIGINT NOT NULL,
            join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, chat_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_warnings (
            user_id BIGINT NOT NULL,
            chat_id BIGINT NOT NULL,
            warning_count INTEGER DEFAULT 0,
            last_warning_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, chat_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kick_logs (
            id SERIAL PRIMARY KEY,
            chat_id BIGINT NOT NULL,
            kicked_by BIGINT NOT NULL,
            kicked_user BIGINT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS members_backup (
            id SERIAL PRIMARY KEY,
            chat_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            backup_date DATE NOT NULL,
            UNIQUE (chat_id, user_id, backup_date)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_cache (
            user_id BIGINT NOT NULL,
            chat_id BIGINT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, chat_id)
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()
    logger.info("Database tables initialized")


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    if not text:
        return ""

    # Remove Arabic diacritics (tashkeel)
    tashkeel = r"[\u064B-\u065F\u0670\u0640]"
    text = re.sub(tashkeel, "", text)

    # Remove zero-width characters
    zero_width = r"[\u200B-\u200F\uFEFF\u2060\u180E]"
    text = re.sub(zero_width, "", text)

    # Normalize alef variants to ุง
    alef_variants = r"[\u0623\u0625\u0622\u0671]"
    text = re.sub(alef_variants, "\u0627", text)

    # Collapse multiple spaces
    text = re.sub(r"\s+", " ", text)

    return text.strip().lower()


# ============================================================
# SPAM DETECTION
# ============================================================

FORBIDDEN_WORDS = [
    normalize_text("\u0631\u0628\u062D \u0633\u0631\u064A\u0639"),      # ุฑุจุญ ุณุฑูุน
    normalize_text("\u0627\u0631\u0628\u062D \u0627\u0644\u0645\u0627\u0644"),   # ุงุฑุจุญ ุงูู…ุงู
    normalize_text("\u0634\u063A\u0644 \u0645\u0646 \u0627\u0644\u0628\u064A\u062A"), # ุดุบู ู…ู ุงูุจูุช
    normalize_text("\u0627\u0633\u062A\u062B\u0645\u0627\u0631 \u0645\u0627\u0644\u064A"), # ุงุณุชุซู…ุงุฑ ู…ุงูู
    normalize_text("\u0633\u0643\u0633"),                              # ุณูุณ
]

LINK_PATTERN = re.compile(
    r"(?:https?://|www\.)"
    r"[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+"
    r"|[a-zA-Z0-9\-]+\.(?:com|net|org|io|me|co|info|biz|xyz|tk|ml|ga|cf|top|club|online|site|link|click|work)\b",
    re.IGNORECASE
)


def contains_forbidden_words(text: str) -> bool:
    normalized = normalize_text(text)
    for word in FORBIDDEN_WORDS:
        escaped = re.escape(word)
        pattern = r"\b" + escaped + r"\b"
        if re.search(pattern, normalized):
            return True
    return False


def contains_links(text: str) -> bool:
    if not text:
        return False
    return bool(LINK_PATTERN.search(text))


# ============================================================
# ADMIN CACHE
# ============================================================

admin_cache: Dict[int, Dict[int, bool]] = {}


def is_admin_cached(chat_id: int, user_id: int) -> bool:
    return admin_cache.get(chat_id, {}).get(user_id, False)


def update_admin_cache(chat_id: int, user_id: int, is_admin: bool):
    if chat_id not in admin_cache:
        admin_cache[chat_id] = {}
    admin_cache[chat_id][user_id] = is_admin

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO admin_cache (user_id, chat_id, is_admin, updated_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, chat_id) DO UPDATE
            SET is_admin = EXCLUDED.is_admin, updated_at = CURRENT_TIMESTAMP
        """, (user_id, chat_id, is_admin))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error("Failed to persist admin cache: %s", e)


def load_admin_cache_from_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT chat_id, user_id, is_admin FROM admin_cache")
        for row in cursor.fetchall():
            chat_id, user_id, is_admin = row
            if chat_id not in admin_cache:
                admin_cache[chat_id] = {}
            admin_cache[chat_id][user_id] = is_admin
        cursor.close()
        conn.close()
        total = sum(len(v) for v in admin_cache.values())
        logger.info("Loaded %d admin entries from DB", total)
    except Exception as e:
        logger.error("Failed to load admin cache: %s", e)


# ============================================================
# DATABASE OPERATIONS
# ============================================================

def record_member_join(user_id: int, chat_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO group_members (user_id, chat_id, join_date)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, chat_id) DO UPDATE
            SET join_date = CURRENT_TIMESTAMP
        """, (user_id, chat_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error("Failed to record member join: %s", e)


def get_member_join_date(user_id: int, chat_id: int) -> Optional[datetime]:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT join_date FROM group_members WHERE user_id = %s AND chat_id = %s",
            (user_id, chat_id)
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        logger.error("Failed to get join date: %s", e)
        return None


def get_warning_count(user_id: int, chat_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT warning_count, last_warning_time FROM user_warnings WHERE user_id = %s AND chat_id = %s",
            (user_id, chat_id)
        )
        result = cursor.fetchone()

        if result:
            count, last_time = result
            if last_time and datetime.now() - last_time > timedelta(days=7):
                cursor.execute(
                    "UPDATE user_warnings SET warning_count = 0, last_warning_time = CURRENT_TIMESTAMP WHERE user_id = %s AND chat_id = %s",
                    (user_id, chat_id)
                )
                conn.commit()
                count = 0
            cursor.close()
            conn.close()
            return count, last_time
        else:
            cursor.close()
            conn.close()
            return 0, None
    except Exception as e:
        logger.error("Failed to get warning count: %s", e)
        return 0, None


def increment_warning(user_id: int, chat_id: int) -> int:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_warnings (user_id, chat_id, warning_count, last_warning_time)
            VALUES (%s, %s, 1, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, chat_id) DO UPDATE
            SET warning_count = user_warnings.warning_count + 1,
                last_warning_time = CURRENT_TIMESTAMP
            RETURNING warning_count
        """, (user_id, chat_id))
        new_count = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        return new_count
    except Exception as e:
        logger.error("Failed to increment warning: %s", e)
        return 0


def log_kick(chat_id: int, kicked_by: int, kicked_user: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO kick_logs (chat_id, kicked_by, kicked_user, timestamp)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
        """, (chat_id, kicked_by, kicked_user))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error("Failed to log kick: %s", e)


def get_recent_kicks(chat_id: int, kicked_by: int, minutes: int = 5) -> int:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM kick_logs
            WHERE chat_id = %s AND kicked_by = %s
            AND timestamp > CURRENT_TIMESTAMP - INTERVAL '%s minutes'
        """, (chat_id, kicked_by, minutes))
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count
    except Exception as e:
        logger.error("Failed to get recent kicks: %s", e)
        return 0


def backup_members(chat_id: int, members: List[int]):
    today = datetime.now().date()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for user_id in members:
            cursor.execute("""
                INSERT INTO members_backup (chat_id, user_id, backup_date)
                VALUES (%s, %s, %s)
                ON CONFLICT (chat_id, user_id, backup_date) DO NOTHING
            """, (chat_id, user_id, today))
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Backed up %d members for chat %s", len(members), chat_id)
    except Exception as e:
        logger.error("Failed to backup members: %s", e)


# ============================================================
# BOT ACTIONS
# ============================================================

async def delete_message_safely(chat_id: int, message_id: int, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        logger.info("Deleted message %s in chat %s", message_id, chat_id)
    except Exception as e:
        logger.warning("Failed to delete message %s: %s", message_id, e)


async def send_temp_notification(chat_id: int, text: str, context: ContextTypes.DEFAULT_TYPE):
    try:
        msg = await context.bot.send_message(chat_id=chat_id, text=text)
        logger.info("Sent temp notification in chat %s", chat_id)

        async def delete_after_delay():
            await asyncio.sleep(10)
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=msg.message_id)
            except Exception:
                pass

        asyncio.create_task(delete_after_delay())
        return msg
    except Exception as e:
        logger.error("Failed to send temp notification: %s", e)


async def ban_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
        logger.info("Banned user %s from chat %s", user_id, chat_id)
        return True
    except Exception as e:
        logger.error("Failed to ban user %s: %s", user_id, e)
        return False


async def mute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.restrict_chat_member(
            chat_id=chat_id,
            user_id=user_id,
            permissions={
                "can_send_messages": False,
                "can_send_media_messages": False,
                "can_send_polls": False,
                "can_send_other_messages": False,
                "can_add_web_page_previews": False,
                "can_change_info": False,
                "can_invite_users": False,
                "can_pin_messages": False,
            }
        )
        logger.info("Muted user %s in chat %s", user_id, chat_id)
        return True
    except Exception as e:
        logger.error("Failed to mute user %s: %s", user_id, e)
        return False


async def notify_owner(context: ContextTypes.DEFAULT_TYPE, text: str):
    try:
        await context.bot.send_message(chat_id=OWNER_ID, text=text)
        logger.info("Sent alert to owner")
    except Exception as e:
        logger.error("Failed to notify owner: %s", e)


async def check_bot_admin_status(chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        bot_member = await context.bot.get_chat_member(chat_id=chat_id, user_id=context.bot.id)
        is_admin = bot_member.status in [ChatMember.ADMINISTRATOR, ChatMember.OWNER]
        if not is_admin:
            logger.critical("Bot is NOT admin in chat %s!", chat_id)
            await send_temp_notification(
                chat_id,
                "\u26A0\uFE0F \u0627\u0644\u0628\u0648\u062A \u0644\u064A\u0633 \u0645\u0634\u0631\u0641\u0627\u064B! \u064A\u0631\u062C\u0649 \u062A\u0631\u0642\u064A\u062A\u0647 \u0625\u0644\u0649 \u0645\u0634\u0631\u0641.",
                context
            )
        return is_admin
    except Exception as e:
        logger.critical("Cannot check bot admin status: %s", e)
        return False


# ============================================================
# MESSAGE HANDLER
# ============================================================

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message and not update.edited_message:
        return

    message = update.message or update.edited_message
    chat_id = message.chat_id
    user_id = message.from_user.id
    text = message.text or message.caption or ""

    logger.debug("Processing message from user %s in chat %s", user_id, chat_id)

    if is_admin_cached(chat_id, user_id):
        logger.debug("User %s is admin, skipping", user_id)
        return

    has_forbidden = contains_forbidden_words(text)
    has_links = contains_links(text)

    if not has_forbidden and not has_links:
        return

    logger.info("Spam detected from user %s: forbidden=%s, links=%s", user_id, has_forbidden, has_links)

    await delete_message_safely(chat_id, message.message_id, context)

    join_date = get_member_join_date(user_id, chat_id)
    is_new_member = False

    if join_date:
        is_new_member = (datetime.now() - join_date) < timedelta(hours=24)
    else:
        record_member_join(user_id, chat_id)
        is_new_member = True

    if is_new_member:
        success = await ban_user(chat_id, user_id, context)
        if success:
            user_name = message.from_user.full_name
            await send_temp_notification(
                chat_id,
                f"\uD83D\uDEAB \u062A\u0645 \u062D\u0638\u0631 \u0627\u0644\u0639\u0636\u0648 \u0627\u0644\u062C\u062F\u064A\u062F ({user_name}) \u0644\u0625\u0631\u0633\u0627\u0644 \u0645\u062D\u062A\u0648\u0649 \u0645\u0645\u0646\u0648\u0639.",
                context
            )
            log_kick(chat_id, context.bot.id, user_id)
        else:
            user_name = message.from_user.full_name
            await send_temp_notification(
                chat_id,
                f"\u26A0\uFE0F \u0641\u0634\u0644 \u062D\u0638\u0631 \u0627\u0644\u0639\u0636\u0648 {user_name}.",
                context
            )
    else:
        warning_count = increment_warning(user_id, chat_id)

        if warning_count >= 3:
            success = await mute_user(chat_id, user_id, context)
            user_name = message.from_user.full_name
            if success:
                await send_temp_notification(
                    chat_id,
                    f"\uD83D\uDD07 \u062A\u0645 \u0643\u062A\u0645 \u0627\u0644\u0639\u0636\u0648 {user_name} \u0628\u0639\u062F 3 \u0645\u062E\u0627\u0644\u0641\u0627\u062A.",
                    context
                )
            else:
                await send_temp_notification(
                    chat_id,
                    f"\u26A0\uFE0F \u0641\u0634\u0644 \u0643\u062A\u0645 \u0627\u0644\u0639\u0636\u0648 {user_name}.",
                    context
                )
        else:
            remaining = 3 - warning_count
            user_name = message.from_user.full_name
            await send_temp_notification(
                chat_id,
                f"\u26A0\uFE0F \u062A\u062D\u0630\u064A\u0631 {warning_count}/3 \u0644\u0644\u0639\u0636\u0648 {user_name}.\n\u0627\u0644\u0645\u062A\u0628\u0642\u064A: {remaining} \u062A\u062D\u0630\u064A\u0631\u0627\u062A \u0642\u0628\u0644 \u0627\u0644\u0643\u062A\u0645.",
                context
            )


# ============================================================
# CHAT MEMBER HANDLERS
# ============================================================

async def handle_chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.chat_member:
        return

    chat_member = update.chat_member
    chat_id = chat_member.chat.id
    user = chat_member.from_user
    new_status = chat_member.new_chat_member
    old_status = chat_member.old_chat_member

    if not user or not new_status:
        return

    user_id = user.id

    if new_status.status == ChatMember.MEMBER and old_status.status == ChatMember.LEFT:
        record_member_join(user_id, chat_id)
        logger.info("New member %s joined chat %s", user_id, chat_id)

    is_admin = new_status.status in [ChatMember.ADMINISTRATOR, ChatMember.OWNER]
    was_admin = old_status.status in [ChatMember.ADMINISTRATOR, ChatMember.OWNER] if old_status else False

    update_admin_cache(chat_id, user_id, is_admin)

    if is_admin and not was_admin and new_status.status == ChatMember.ADMINISTRATOR:
        user_name = user.full_name
        await notify_owner(
            context,
            f"\u26A0\uFE0F \u062A\u0646\u0628\u064A\u0647: \u062A\u0645 \u062A\u0631\u0642\u064A\u0629 \u0639\u0636\u0648 \u062C\u062F\u064A\u062F \u0625\u0644\u0649 \u0645\u0634\u0631\u0641\n\uD83D\uDC64 \u0627\u0644\u0627\u0633\u0645: {user_name}\n\uD83C\uDD94 \u0627\u0644\u0645\u0639\u0631\u0641: {user_id}\n\uD83D\uDCAC \u0627\u0644\u0645\u062C\u0645\u0648\u0639\u0629: {chat_id}"
        )
        logger.warning("New admin promoted: %s in chat %s", user_id, chat_id)


# ============================================================
# COMMANDS
# ============================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        await update.message.reply_text(
            "\uD83D\uDEE1\uFE0F **\u0628\u0648\u062A \u0627\u0644\u062D\u0645\u0627\u064A\u0629 \u0645\u0646 \u0627\u0644\u0633\u0628\u0627\u0645**\n\n"
            "\u0623\u0636\u0641\u0646\u064A \u0625\u0644\u0649 \u0645\u062C\u0645\u0648\u0639\u062A\u0643 \u0648\u0627\u062C\u0639\u0644\u0646\u064A \u0645\u0634\u0631\u0641\u0627\u064B \u0644\u062D\u0645\u0627\u064A\u062A\u0647\u0627.",
            parse_mode="Markdown"
        )
    else:
        await check_bot_admin_status(update.effective_chat.id, context)


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin_cached(update.effective_chat.id, update.effective_user.id):
        return

    chat_id = update.effective_chat.id
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM group_members WHERE chat_id = %s", (chat_id,))
        total_members = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM kick_logs WHERE chat_id = %s", (chat_id,))
        total_kicks = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM kick_logs 
            WHERE chat_id = %s AND timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
        """, (chat_id,))
        recent_kicks = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        await update.message.reply_text(
            f"\uD83D\uDCCA **\u0625\u062D\u0635\u0627\u0626\u064A\u0627\u062A \u0627\u0644\u0645\u062C\u0645\u0648\u0639\u0629**\n\n"
            f"\uD83D\uDC65 \u0627\u0644\u0623\u0639\u0636\u0627\u0621 \u0627\u0644\u0645\u0633\u062C\u0644\u064A\u0646: {total_members}\n"
            f"\uD83D\uDD28 \u0625\u062C\u0645\u0627\u0644\u064A \u0627\u0644\u0637\u0631\u062F\u0627\u062A: {total_kicks}\n"
            f"\u23F0 \u0627\u0644\u0637\u0631\u062F\u0627\u062A (24\u0633): {recent_kicks}",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.error("Failed to get stats: %s", e)
        await update.message.reply_text("\u274C \u0641\u0634\u0644 \u062C\u0644\u0628 \u0627\u0644\u0625\u062D\u0635\u0627\u0626\u064A\u0627\u062A.")


# ============================================================
# DAILY BACKUP JOB
# ============================================================

async def daily_backup_job(context: ContextTypes.DEFAULT_TYPE):
    logger.info("Starting daily backup job...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT chat_id FROM group_members")
        chats = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()

        for chat_id in chats:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT user_id FROM group_members WHERE chat_id = %s", (chat_id,))
                tracked_members = [row[0] for row in cursor.fetchall()]
                cursor.close()
                conn.close()

                backup_members(chat_id, tracked_members)
            except Exception as e:
                logger.error("Failed to backup chat %s: %s", chat_id, e)
    except Exception as e:
        logger.error("Failed daily backup: %s", e)


# ============================================================
# FLASK WEBHOOK SERVER
# ============================================================

flask_app = Flask(__name__)
bot_app: Optional[Application] = None


@flask_app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200


@flask_app.route(f"/webhook/{WEBHOOK_SECRET}", methods=["POST"])
def webhook():
    if request.method == "POST":
        try:
            update = Update.de_json(request.get_json(force=True), bot_app.bot)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(bot_app.process_update(update))
            loop.close()

            return "OK", 200
        except Exception as e:
            logger.error("Webhook error: %s", e)
            return "Error", 500
    return "Method not allowed", 405


# ============================================================
# MAIN
# ============================================================

def setup_bot() -> Application:
    global bot_app

    init_database()
    load_admin_cache_from_db()

    bot_app = Application.builder().token(BOT_TOKEN).build()

    bot_app.add_handler(CommandHandler("start", start_command))
    bot_app.add_handler(CommandHandler("stats", stats_command))

    bot_app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & filters.ChatType.GROUPS,
        handle_message
    ))
    bot_app.add_handler(MessageHandler(
        filters.ChatType.GROUPS & filters.UpdateType.EDITED_MESSAGE,
        handle_message
    ))

    bot_app.add_handler(ChatMemberHandler(handle_chat_member_update, ChatMemberHandler.CHAT_MEMBER))

    job_queue = bot_app.job_queue
    if job_queue:
        job_queue.run_daily(daily_backup_job, time=datetime.time(hour=3, minute=0))

    logger.info("Bot application configured successfully")
    return bot_app


async def setup_webhook():
    if WEBHOOK_URL:
        webhook_full_url = f"{WEBHOOK_URL}/webhook/{WEBHOOK_SECRET}"
        await bot_app.bot.set_webhook(url=webhook_full_url)
        logger.info("Webhook set to: %s", webhook_full_url)


def run():
    logger.info("Starting Anti-Spam Bot...")

    setup_bot()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot_app.initialize())
    loop.run_until_complete(setup_webhook())
    loop.close()

    logger.info("Starting Flask server on port %s", PORT)
    flask_app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    run()