"""
One-time script to generate a Telethon StringSession for the Telegram CTI connector.
Run this ONCE on your machine (not in Docker) to authenticate:

    pip install telethon
    python generate_tg_session.py

Paste the printed session string into your .env as TG_SESSION=<string>.
The session is reusable — no phone re-auth needed after that.

Get TG_API_ID and TG_API_HASH at https://my.telegram.org/apps (free).
"""
import os

try:
    from telethon.sync import TelegramClient
    from telethon.sessions import StringSession
except ImportError:
    print("ERROR: telethon not installed. Run: pip install telethon")
    raise SystemExit(1)

api_id_raw = os.getenv("TG_API_ID") or input("Enter TG_API_ID: ").strip()
api_hash = os.getenv("TG_API_HASH") or input("Enter TG_API_HASH: ").strip()

try:
    api_id = int(api_id_raw)
except ValueError:
    print("ERROR: TG_API_ID must be an integer.")
    raise SystemExit(1)

print("\nOpening Telegram login (phone number required for first-time auth)...")
with TelegramClient(StringSession(), api_id, api_hash) as client:
    session_string = client.session.save()

print("\n" + "=" * 60)
print("SUCCESS. Add this to your .env file:")
print()
print(f"TG_API_ID={api_id}")
print(f"TG_API_HASH={api_hash}")
print(f"TG_SESSION={session_string}")
print()
print("TG_CTI_CHANNELS=darkwebinformer,H4ckManac,vxunderground,RansomwareNews")
print("=" * 60)
print("\nThe session string authenticates as your Telegram account.")
print("Keep it secret — treat it like a password.")
