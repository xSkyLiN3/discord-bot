# discord_bot.py — Bot de Discord -> HLDS RCON (GoldSrc)
# pip install discord.py
import os
import discord
from hlds_rcon_debug import hlds_rcon

DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "")
CHANNEL_ID = int(os.environ.get("CHANNEL_ID", "0"))

RCON_IP       = os.environ.get("RCON_IP", "")
RCON_PORT     = int(os.environ.get("RCON_PORT", "27015"))
RCON_PASSWORD = os.environ.get("RCON_PASSWORD", "")

# Prefijo de comando en Discord
PREFIX = ""   # Ej: "!cs hola" -> say en el server

# --------- Config Discord ---------
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)

def sanitize_for_discord_say(s: str) -> str:
    # Limpia saltos/pipe y evita @everyone/@here
    s = (s or "").replace("\r", " ").replace("\n", " ").replace("|", "¦")
    s = s.replace("@everyone", "@ everyone").replace("@here", "@ here")
    return s.strip()

def esc_quotes(s: str) -> str:
    # Reemplaza comillas dobles para no romper el parser del SRV command
    return s.replace('"', "'")

@bot.event
async def on_ready():
    print(f"Bot listo como {bot.user} (canal objetivo: {CHANNEL_ID})")

@bot.event
async def on_message(msg: discord.Message):
    if msg.author.bot or msg.channel.id != CHANNEL_ID:
        return

    content = (msg.content or "").strip()
    if not content.startswith(PREFIX):
        return

    text = sanitize_for_discord_say(content[len(PREFIX):])
    if not text:
        return

    canal  = esc_quotes(msg.channel.name)
    autor  = esc_quotes(msg.author.display_name or msg.author.name)
    texto  = esc_quotes(text)

    # Llama al SRV command de tu plugin AMXX:
    cmd = f'discord_say "{canal}" "{autor}" "{texto}"'

    try:
        _ = hlds_rcon(RCON_IP, RCON_PORT, RCON_PASSWORD, cmd)
        await msg.add_reaction("✅")
    except Exception as e:
        await msg.reply(f"RCON error: {e}")

if __name__ == "__main__":
    if not DISCORD_TOKEN or not CHANNEL_ID or not RCON_PASSWORD:
        raise SystemExit("Faltan DISCORD_TOKEN / CHANNEL_ID / RCON_PASSWORD.")
    bot.run(DISCORD_TOKEN)