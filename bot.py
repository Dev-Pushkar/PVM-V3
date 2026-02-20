# bot.py
import discord
from discord.ext import commands
import asyncio
import subprocess
import json
from datetime import datetime, timedelta
import shlex
import logging
import shutil
import os
from typing import Optional, List, Dict, Any
import sqlite3
import random
import traceback
import aiohttp

# ============ CONFIGURATION ============

DISCORD_TOKEN = ''
BOT_NAME = 'PVMLIX'
PREFIX = '.'
YOUR_SERVER_IP = ''
MAIN_ADMIN_ID = '1372237657207345183'
VPS_USER_ROLE_ID = ''
DEFAULT_STORAGE_POOL = 'default'

# Banner and Thumbnail URLs
THUMBNAIL = "https://images-ext-1.discordapp.net/external/SJ37GTKBX-zrhHznp2QEBsg9b0bx9JodgsMvjudCpDM/%3Fsize%3D1024/https/cdn.discordapp.com/avatars/1372237657207345183/31cbfcc148c7dcacd37417750a507fe6.webp?format=webp"
BANNER = "https://i.imgur.com/your-banner-image.png"  # Replace with your banner URL

# Free VPS Plans based on invites/boosts
FREE_VPS_PLANS = {
    'invites': [
        {'name': 'Free Tier I', 'invites': 10, 'ram': 12, 'cpu': 4, 'disk': 100},
        {'name': 'Free Tier II', 'invites': 20, 'ram': 24, 'cpu': 6, 'disk': 250},
        {'name': 'Free Tier III', 'invites': 28, 'ram': 32, 'cpu': 8, 'disk': 300}
    ],
    'boosts': [
        {'name': 'Boost Reward I', 'boosts': 1, 'ram': 24, 'cpu': 6, 'disk': 250},
        {'name': 'Boost Reward II', 'boosts': 2, 'ram': 32, 'cpu': 8, 'disk': 300}
    ]
}

# OS Options for VPS Creation and Reinstall
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu:20.04"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu:22.04"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu:24.04"},
    {"label": "Debian 10 (Buster)", "value": "images:debian/10"},
    {"label": "Debian 11 (Bullseye)", "value": "images:debian/11"},
    {"label": "Debian 12 (Bookworm)", "value": "images:debian/12"},
    {"label": "Debian 13 (Trixie)", "value": "images:debian/13"},
    {"label": "Rocky Linux 9", "value": "images:rockylinux/9"},
    {"label": "AlmaLinux 9", "value": "images:almalinux/9"},
    {"label": "Fedora 39", "value": "images:fedora/39"},
]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(f'{BOT_NAME.lower()}_vps_bot')

# Check if lxc command is available
if not shutil.which("lxc"):
    logger.error("LXC command not found. Please ensure LXC is installed.")
    raise SystemExit("LXC command not found. Please ensure LXC is installed.")

# ============ DATABASE SETUP ============

def get_db():
    conn = sqlite3.connect('vps.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    # Admins table
    cur.execute('''CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY
    )''')
    cur.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (str(MAIN_ADMIN_ID),))
    
    # VPS table
    cur.execute('''CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT UNIQUE NOT NULL,
        plan_name TEXT DEFAULT 'Custom',
        ram TEXT NOT NULL,
        cpu TEXT NOT NULL,
        storage TEXT NOT NULL,
        config TEXT NOT NULL,
        os_version TEXT DEFAULT 'ubuntu:22.04',
        status TEXT DEFAULT 'stopped',
        suspended INTEGER DEFAULT 0,
        whitelisted INTEGER DEFAULT 0,
        suspended_reason TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        shared_with TEXT DEFAULT '[]',
        suspension_history TEXT DEFAULT '[]'
    )''')
    
    # Ensure columns exist
    cur.execute('PRAGMA table_info(vps)')
    info = cur.fetchall()
    columns = [col[1] for col in info]
    if 'os_version' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN os_version TEXT DEFAULT 'ubuntu:22.04'")
    if 'plan_name' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN plan_name TEXT DEFAULT 'Custom'")
    if 'suspended_reason' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN suspended_reason TEXT DEFAULT ''")
    
    # User stats for free VPS
    cur.execute('''CREATE TABLE IF NOT EXISTS user_stats (
        user_id TEXT PRIMARY KEY,
        invites INTEGER DEFAULT 0,
        boosts INTEGER DEFAULT 0,
        credits INTEGER DEFAULT 0,
        claimed_free_vps INTEGER DEFAULT 0,
        last_daily TEXT,
        last_updated TEXT
    )''')
    
    # Settings table
    cur.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')
    
    # Port allocations table
    cur.execute('''CREATE TABLE IF NOT EXISTS port_allocations (
        user_id TEXT PRIMARY KEY,
        allocated_ports INTEGER DEFAULT 0
    )''')
    
    # Port forwards table
    cur.execute('''CREATE TABLE IF NOT EXISTS port_forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        vps_container TEXT NOT NULL,
        vps_port INTEGER NOT NULL,
        host_port INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )''')
    
    # Suspension logs table
    cur.execute('''CREATE TABLE IF NOT EXISTS suspension_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        container_name TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        reason TEXT,
        admin_id TEXT,
        created_at TEXT NOT NULL
    )''')
    
    # Initialize settings
    settings_init = [
        ('cpu_threshold', '90'),
        ('ram_threshold', '90'),
        ('maintenance_mode', 'false'),
        ('maintenance_started_by', ''),
        ('maintenance_started_at', ''),
        ('bot_version', '4.1.0'),
        ('bot_status', 'online'),
        ('bot_activity', 'watching'),
        ('bot_activity_name', f'{BOT_NAME} VPS Manager'),
        ('daily_credit_amount', '10')
    ]
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    
    conn.commit()
    conn.close()

def get_setting(key: str, default: Any = None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def get_vps_data() -> Dict[str, List[Dict[str, Any]]]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM vps')
    rows = cur.fetchall()
    conn.close()
    data = {}
    for row in rows:
        user_id = row['user_id']
        if user_id not in data:
            data[user_id] = []
        vps = dict(row)
        vps['shared_with'] = json.loads(vps['shared_with'])
        vps['suspension_history'] = json.loads(vps['suspension_history'])
        vps['suspended'] = bool(vps['suspended'])
        vps['whitelisted'] = bool(vps['whitelisted'])
        vps['os_version'] = vps.get('os_version', 'ubuntu:22.04')
        vps['plan_name'] = vps.get('plan_name', 'Custom')
        data[user_id].append(vps)
    return data

def get_admins() -> List[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id FROM admins')
    rows = cur.fetchall()
    conn.close()
    return [row['user_id'] for row in rows]

def save_vps_data():
    conn = get_db()
    cur = conn.cursor()
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            shared_json = json.dumps(vps['shared_with'])
            history_json = json.dumps(vps['suspension_history'])
            suspended_int = 1 if vps['suspended'] else 0
            whitelisted_int = 1 if vps.get('whitelisted', False) else 0
            os_ver = vps.get('os_version', 'ubuntu:22.04')
            plan_name = vps.get('plan_name', 'Custom')
            created_at = vps.get('created_at', datetime.now().isoformat())
            suspended_reason = vps.get('suspended_reason', '')
            
            if 'id' not in vps or vps['id'] is None:
                cur.execute('''INSERT INTO vps (user_id, container_name, plan_name, ram, cpu, storage, config, os_version, status, suspended, whitelisted, suspended_reason, created_at, shared_with, suspension_history)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (user_id, vps['container_name'], plan_name, vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int, suspended_reason,
                             created_at, shared_json, history_json))
                vps['id'] = cur.lastrowid
            else:
                cur.execute('''UPDATE vps SET user_id = ?, plan_name = ?, ram = ?, cpu = ?, storage = ?, config = ?, os_version = ?, status = ?, suspended = ?, whitelisted = ?, suspended_reason = ?, shared_with = ?, suspension_history = ?
                               WHERE id = ?''',
                            (user_id, plan_name, vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int, suspended_reason,
                             shared_json, history_json, vps['id']))
    conn.commit()
    conn.close()

def save_admin_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM admins')
    for admin_id in admin_data['admins']:
        cur.execute('INSERT INTO admins (user_id) VALUES (?)', (admin_id,))
    conn.commit()
    conn.close()

def log_suspension(container_name: str, user_id: str, action: str, reason: str = "", admin_id: str = ""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''INSERT INTO suspension_logs (container_name, user_id, action, reason, admin_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (container_name, user_id, action, reason, admin_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_suspension_logs(container_name: str = None) -> List[Dict]:
    conn = get_db()
    cur = conn.cursor()
    if container_name:
        cur.execute('SELECT * FROM suspension_logs WHERE container_name = ? ORDER BY created_at DESC', (container_name,))
    else:
        cur.execute('SELECT * FROM suspension_logs ORDER BY created_at DESC LIMIT 50')
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# User stats functions
def get_user_stats(user_id: str) -> Dict[str, Any]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM user_stats WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {'user_id': user_id, 'invites': 0, 'boosts': 0, 'credits': 0, 'claimed_free_vps': 0, 'last_daily': None, 'last_updated': None}

def update_user_stats(user_id: str, invites: int = 0, boosts: int = 0, credits: int = 0, claimed_free_vps: int = 0, last_daily: str = None):
    conn = get_db()
    cur = conn.cursor()
    
    if last_daily:
        cur.execute('''INSERT OR REPLACE INTO user_stats 
                       (user_id, invites, boosts, credits, claimed_free_vps, last_daily, last_updated) 
                       VALUES (?, COALESCE((SELECT invites FROM user_stats WHERE user_id = ?), 0) + ?, 
                               COALESCE((SELECT boosts FROM user_stats WHERE user_id = ?), 0) + ?,
                               COALESCE((SELECT credits FROM user_stats WHERE user_id = ?), 0) + ?,
                               COALESCE((SELECT claimed_free_vps FROM user_stats WHERE user_id = ?), 0) + ?,
                               ?, ?)''',
                    (user_id, user_id, invites, user_id, boosts, user_id, credits, user_id, claimed_free_vps, last_daily, datetime.now().isoformat()))
    else:
        cur.execute('''INSERT OR REPLACE INTO user_stats 
                       (user_id, invites, boosts, credits, claimed_free_vps, last_updated) 
                       VALUES (?, COALESCE((SELECT invites FROM user_stats WHERE user_id = ?), 0) + ?, 
                               COALESCE((SELECT boosts FROM user_stats WHERE user_id = ?), 0) + ?,
                               COALESCE((SELECT credits FROM user_stats WHERE user_id = ?), 0) + ?,
                               COALESCE((SELECT claimed_free_vps FROM user_stats WHERE user_id = ?), 0) + ?,
                               ?)''',
                    (user_id, user_id, invites, user_id, boosts, user_id, credits, user_id, claimed_free_vps, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

# Port forwarding functions
def get_user_allocation(user_id: str) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT allocated_ports FROM port_allocations WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else 0

def get_user_used_ports(user_id: str) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM port_forwards WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0]

def allocate_ports(user_id: str, amount: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO port_allocations (user_id, allocated_ports) VALUES (?, COALESCE((SELECT allocated_ports FROM port_allocations WHERE user_id = ?), 0) + ?)', (user_id, user_id, amount))
    conn.commit()
    conn.close()

def deallocate_ports(user_id: str, amount: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE port_allocations SET allocated_ports = GREATEST(0, allocated_ports - ?) WHERE user_id = ?', (amount, user_id))
    conn.commit()
    conn.close()

def get_available_host_port() -> Optional[int]:
    used_ports = set()
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT host_port FROM port_forwards')
    for row in cur.fetchall():
        used_ports.add(row[0])
    conn.close()
    for _ in range(100):
        port = random.randint(20000, 50000)
        if port not in used_ports:
            return port
    return None

async def create_port_forward(user_id: str, container: str, vps_port: int) -> Optional[int]:
    host_port = get_available_host_port()
    if not host_port:
        return None
    try:
        await execute_lxc(f"lxc config device add {container} tcp_proxy_{host_port} proxy listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port}")
        await execute_lxc(f"lxc config device add {container} udp_proxy_{host_port} proxy listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port}")
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO port_forwards (user_id, vps_container, vps_port, host_port, created_at) VALUES (?, ?, ?, ?, ?)',
                    (user_id, container, vps_port, host_port, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return host_port
    except Exception as e:
        logger.error(f"Failed to create port forward: {e}")
        return None

async def remove_port_forward(forward_id: int, is_admin: bool = False) -> tuple[bool, Optional[str]]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id, vps_container, host_port FROM port_forwards WHERE id = ?', (forward_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False, None
    user_id, container, host_port = row
    try:
        await execute_lxc(f"lxc config device remove {container} tcp_proxy_{host_port}")
        await execute_lxc(f"lxc config device remove {container} udp_proxy_{host_port}")
        cur.execute('DELETE FROM port_forwards WHERE id = ?', (forward_id,))
        conn.commit()
        conn.close()
        return True, user_id
    except Exception as e:
        logger.error(f"Failed to remove port forward {forward_id}: {e}")
        conn.close()
        return False, None

def get_user_forwards(user_id: str) -> List[Dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM port_forwards WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Initialize database
init_db()

# Load data at startup
vps_data = get_vps_data()
admin_data = {'admins': get_admins()}

# Global settings from DB
CPU_THRESHOLD = int(get_setting('cpu_threshold', 90))
RAM_THRESHOLD = int(get_setting('ram_threshold', 90))
MAINTENANCE_MODE = get_setting('maintenance_mode', 'false').lower() == 'true'
MAINTENANCE_STARTED_BY = get_setting('maintenance_started_by', '')
MAINTENANCE_STARTED_AT = get_setting('maintenance_started_at', '')
BOT_STATUS = get_setting('bot_status', 'online')
BOT_ACTIVITY = get_setting('bot_activity', 'watching')
BOT_ACTIVITY_NAME = get_setting('bot_activity_name', f'{BOT_NAME} VPS Manager')
DAILY_CREDIT_AMOUNT = int(get_setting('daily_credit_amount', 10))

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# Dictionary to track active help menus to prevent duplicates
active_help_menus = {}

# Helper function to truncate text
def truncate_text(text, max_length=1024):
    if not text:
        return text
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Embed creation functions with proper thumbnail and banner handling
def create_embed(title, description="", color=0x1a1a1a):
    embed = discord.Embed(
        title=f"☁️ {title}",
        description=truncate_text(description, 4096),
        color=color
    )
    
    # Set thumbnail if URL is provided and valid (small image at top right)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    
    # Set banner/image if URL is provided and valid (small banner at top)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    return embed

def add_field(embed, name, value, inline=False):
    embed.add_field(
        name=f"⌯⌲ {name}",
        value=truncate_text(value, 1024),
        inline=inline
    )
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=0x00ff88)

def create_error_embed(title, description=""):
    embed = discord.Embed(
        title=f"☁️ {title}",
        description=f"───────────────\n{description}\n───────────────",
        color=0xff3366
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    return embed

def create_info_embed(title, description=""):
    return create_embed(title, description, color=0x00ccff)

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=0xffaa00)

# ============ MAINTENANCE MODE CHECK ============

async def maintenance_check(ctx):
    global MAINTENANCE_MODE, MAINTENANCE_STARTED_BY, MAINTENANCE_STARTED_AT
    
    if MAINTENANCE_MODE:
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        
        try:
            started_by_user = await bot.fetch_user(int(MAINTENANCE_STARTED_BY)) if MAINTENANCE_STARTED_BY else None
            started_by_mention = started_by_user.mention if started_by_user else "Unknown"
        except:
            started_by_mention = "Unknown"
        
        try:
            started_at = datetime.fromisoformat(MAINTENANCE_STARTED_AT).strftime('%Y-%m-%d %H:%M:%S') if MAINTENANCE_STARTED_AT else "Unknown"
        except:
            started_at = "Unknown"
        
        embed = discord.Embed(
            title="🔧 Maintenance Mode Active",
            description="The bot is currently under maintenance. Only administrators can use commands at this time.",
            color=0xffaa00
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.add_field(name="⌯⌲ Started By", value=started_by_mention, inline=True)
        embed.add_field(name="⌯⌲ Status", value="Commands disabled for non-admins", inline=True)
        embed.add_field(name="⌯⌲ Started At", value=started_at, inline=False)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        
        await ctx.send(embed=embed)
        return False
    return True

# ============ ADMIN CHECKS ============

def is_admin():
    async def predicate(ctx):
        if not await maintenance_check(ctx):
            return False
        
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        raise commands.CheckFailure("You need admin permissions to use this command.")
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if not await maintenance_check(ctx):
            return False
        
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        raise commands.CheckFailure("Only the main admin can use this command.")
    return commands.check(predicate)

# ============ LXC COMMAND EXECUTION ============

async def execute_lxc(command, timeout=120):
    try:
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError(f"Command timed out after {timeout} seconds")
        if proc.returncode != 0:
            error = stderr.decode().strip() if stderr else "Command failed with no error output"
            raise Exception(error)
        return stdout.decode().strip() if stdout else True
    except asyncio.TimeoutError as te:
        logger.error(f"LXC command timed out: {command} - {str(te)}")
        raise
    except Exception as e:
        logger.error(f"LXC Error: {command} - {str(e)}")
        raise

# ============ LXC CONFIGURATION ============

async def apply_lxc_config(container_name):
    try:
        await execute_lxc(f"lxc config set {container_name} security.nesting true")
        await execute_lxc(f"lxc config set {container_name} security.privileged true")
        await execute_lxc(f"lxc config set {container_name} security.syscalls.intercept.mknod true")
        await execute_lxc(f"lxc config set {container_name} security.syscalls.intercept.setxattr true")
        
        try:
            await execute_lxc(f"lxc config device add {container_name} fuse unix-char path=/dev/fuse")
        except Exception as e:
            if "already exists" not in str(e).lower():
                raise
        
        await execute_lxc(f"lxc config set {container_name} linux.kernel_modules overlay,loop,nf_nat,ip_tables,ip6_tables,netlink_diag,br_netfilter")
        
        raw_lxc_config = """
lxc.apparmor.profile = unconfined
lxc.cgroup.devices.allow = a
lxc.cap.drop =
lxc.mount.auto = proc:rw sys:rw cgroup:rw
"""
        await execute_lxc(f"lxc config set {container_name} raw.lxc '{raw_lxc_config}'")
        
        logger.info(f"Applied LXC config to {container_name}")
    except Exception as e:
        logger.error(f"Failed to apply LXC config to {container_name}: {e}")

async def apply_internal_permissions(container_name):
    try:
        await asyncio.sleep(5)
        
        commands = [
            "mkdir -p /etc/sysctl.d/",
            "echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/99-custom.conf",
            "echo 'net.ipv4.ping_group_range=0 2147483647' >> /etc/sysctl.d/99-custom.conf",
            "echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-custom.conf",
            "sysctl -p /etc/sysctl.d/99-custom.conf || true"
        ]
        
        for cmd in commands:
            try:
                await execute_lxc(f"lxc exec {container_name} -- bash -c \"{cmd}\"")
            except Exception:
                continue
        
        logger.info(f"Applied internal permissions to {container_name}")
    except Exception as e:
        logger.error(f"Failed to apply internal permissions to {container_name}: {e}")

# ============ VPS USER ROLE ============

async def get_or_create_vps_role(guild):
    global VPS_USER_ROLE_ID
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    role = discord.utils.get(guild.roles, name=f"{BOT_NAME} VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    try:
        role = await guild.create_role(
            name=f"{BOT_NAME} VPS User",
            color=discord.Color.dark_purple(),
            reason=f"{BOT_NAME} VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created {BOT_NAME} VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create {BOT_NAME} VPS User role: {e}")
        return None

# ============ CONTAINER STATS FUNCTIONS ============

async def get_container_status(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if line.startswith("Status: "):
                return line.split(": ", 1)[1].strip().lower()
        return "unknown"
    except Exception:
        return "unknown"

async def get_container_cpu(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "top", "-bn1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if '%Cpu(s):' in line:
                parts = line.split()
                us = float(parts[1])
                sy = float(parts[3])
                ni = float(parts[5])
                id_ = float(parts[7])
                wa = float(parts[9])
                hi = float(parts[11])
                si = float(parts[13])
                st = float(parts[15])
                usage = us + sy + ni + wa + hi + si + st
                return f"{usage:.1f}%"
        return "0.0%"
    except Exception:
        return "N/A"

async def get_container_memory(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return f"{used}/{total} MB ({usage_pct:.1f}%)"
        return "Unknown"
    except Exception:
        return "N/A"

async def get_container_disk(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines:
            if '/dev/' in line and ' /' in line:
                parts = line.split()
                if len(parts) >= 5:
                    used = parts[2]
                    size = parts[1]
                    perc = parts[4]
                    return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception:
        return "N/A"

async def get_container_uptime(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "uptime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        uptime_str = stdout.decode().strip()
        if ',' in uptime_str:
            uptime_parts = uptime_str.split('up ')[1].split(',')[0]
            return uptime_parts.strip()
        return uptime_str
    except Exception:
        return "Unknown"

async def get_container_logs(container_name, lines=50):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "journalctl", "-n", str(lines), "--no-pager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() if stdout else "No logs available"
    except Exception:
        return "Unable to fetch logs"

def get_uptime():
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

# ============ BOT EVENTS ============

@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    
    if MAINTENANCE_MODE:
        await bot.change_presence(status=discord.Status.idle, activity=discord.Game(name="🔧 Maintenance Mode"))
    else:
        activity_types = {
            'playing': discord.ActivityType.playing,
            'watching': discord.ActivityType.watching,
            'listening': discord.ActivityType.listening,
        }
        
        status_types = {
            'online': discord.Status.online,
            'idle': discord.Status.idle,
            'dnd': discord.Status.dnd,
        }
        
        activity_type = activity_types.get(BOT_ACTIVITY, discord.ActivityType.watching)
        status = status_types.get(BOT_STATUS, discord.Status.online)
        
        await bot.change_presence(
            status=status,
            activity=discord.Activity(type=activity_type, name=BOT_ACTIVITY_NAME)
        )
    
    logger.info(f"{BOT_NAME} Bot is ready!")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing Argument", f"Please check command usage with `{PREFIX}help`."))
    elif isinstance(error, commands.BadArgument):
        await ctx.send(embed=create_error_embed("Invalid Argument", "Please check your input and try again."))
    elif isinstance(error, commands.CheckFailure):
        error_msg = str(error) if str(error) else "You need admin permissions for this command."
        await ctx.send(embed=create_error_embed("Access Denied", error_msg))
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(embed=create_warning_embed("Command on Cooldown", f"Please wait {error.retry_after:.2f} seconds before using this command again."))
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("System Error", "An unexpected error occurred."))

# ============ USER COMMANDS ============

@bot.command(name='ping')
@commands.cooldown(1, 3, commands.BucketType.user)
async def ping(ctx):
    """Check bot latency"""
    if not await maintenance_check(ctx):
        return
    
    latency = round(bot.latency * 1000)
    
    embed = discord.Embed(
        title="🏓 Pong!",
        description=f"{BOT_NAME} Bot latency: `{latency}ms`",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    
    await ctx.send(embed=embed)

@bot.command(name='uptime')
@commands.cooldown(1, 5, commands.BucketType.user)
async def uptime(ctx):
    """Show host uptime"""
    if not await maintenance_check(ctx):
        return
    
    up = get_uptime()
    embed = discord.Embed(
        title="⏱️ Host Uptime",
        description=f"```\n{up}\n```",
        color=0x00ccff
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='plans')
@commands.cooldown(1, 5, commands.BucketType.user)
async def show_plans(ctx):
    """View free VPS plans"""
    if not await maintenance_check(ctx):
        return
    
    embed = discord.Embed(
        title="☁️ Free VPS Plans ☁️",
        description="───────────────\nEarn FREE VPS plans by invites or boosts",
        color=0xffaa00
    )
    
    for plan in FREE_VPS_PLANS['invites']:
        plan_text = f"⌯⌲ RAM: {plan['ram']} GB\n"
        plan_text += f"⌯⌲ CPU: {plan['cpu']} Cores\n"
        plan_text += f"⌯⌲ Storage: {plan['disk']} GB\n"
        plan_text += f"⌯⌲ Network: Private IPv4"
        
        embed.add_field(
            name=f"⌯⌲ {plan['name']} — {plan['invites']} Invites",
            value=plan_text,
            inline=False
        )
        embed.add_field(name="───────────────", value=f"Requirement: {plan['invites']} Server Invites", inline=False)
    
    for plan in FREE_VPS_PLANS['boosts']:
        plan_text = f"⌯⌲ RAM: {plan['ram']} GB\n"
        plan_text += f"⌯⌲ CPU: {plan['cpu']} Cores\n"
        plan_text += f"⌯⌲ Storage: {plan['disk']} GB\n"
        plan_text += f"⌯⌲ Network: Private IPv4"
        
        embed.add_field(
            name=f"⌯⌲ {plan['name']} — {plan['boosts']} Boost",
            value=plan_text,
            inline=False
        )
        embed.add_field(name="───────────────", value=f"Requirement: {plan['boosts']} Server Boost", inline=False)
    
    embed.add_field(name="───────────────", value=f"⌯⌲ Use `{PREFIX}claimfree` to claim your Free VPS Plan", inline=False)
    embed.add_field(name="───────────────", value="Earn credits by inviting users or boosting the server", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    
    await ctx.send(embed=embed)

@bot.command(name='freeplans')
@commands.cooldown(1, 5, commands.BucketType.user)
async def free_plans(ctx):
    """Free Plans List"""
    if not await maintenance_check(ctx):
        return
    await show_plans(ctx)

@bot.command(name='myvps')
@commands.cooldown(1, 5, commands.BucketType.user)
async def my_vps(ctx):
    """List your VPS"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    
    if not vps_list:
        embed = discord.Embed(
            title="☁️ No VPS Found",
            description="You don't have any VPS. Do invites or boosts to get one.",
            color=0xff3366
        )
        embed.add_field(
            name="⌯⌲ Quick Actions",
            value=f"`.plans`",
            inline=False
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
        return
    
    embed = discord.Embed(
        title="🖥️ My VPS",
        description=f"You have `{len(vps_list)}` VPS",
        color=0x00ccff
    )
    
    for i, vps in enumerate(vps_list, 1):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        
        status_emoji = "🟢" if vps.get('status') == 'running' else "🔴" if vps.get('status') == 'stopped' else "🟡"
        
        vps_info = f"{status_emoji} **VPS #{i}:** `{vps['container_name']}`\n"
        vps_info += f"• **Status:** {status}\n"
        vps_info += f"• **Plan:** {vps.get('plan_name', 'Custom')}\n"
        vps_info += f"• **Resources:** {vps.get('config', 'Custom')}\n"
        
        embed.add_field(name="", value=vps_info, inline=False)
    
    embed.add_field(name="⌯⌲ Management", value=f"Use `{PREFIX}manage` to control your VPS\nUse `{PREFIX}list` for detailed information", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='list')
@commands.cooldown(1, 5, commands.BucketType.user)
async def list_user_vps(ctx):
    """Detailed VPS list"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    
    if not vps_list:
        embed = discord.Embed(
            title="☁️ No VPS Found",
            description="You don't have any VPS. Do invites or boosts to get one.",
            color=0xff3366
        )
        embed.add_field(
            name="⌯⌲ Quick Actions",
            value=f"`.plans`",
            inline=False
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
        return
    
    embed = discord.Embed(
        title="📋 Your VPS List",
        description=f"Showing `{len(vps_list)}` VPS for {ctx.author.mention}",
        color=0x00ccff
    )
    
    for i, vps in enumerate(vps_list, 1):
        container_name = vps['container_name']
        
        status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime_info = await get_container_uptime(container_name)
        
        status_emoji = "🟢" if status == 'running' else "🔴" if status == 'stopped' else "🟡"
        suspended_text = " (SUSPENDED)" if vps.get('suspended', False) else ""
        
        vps_info = f"**#{i} | {status_emoji} {status.upper()}{suspended_text}**\n"
        vps_info += f"**Container:** `{container_name}`\n"
        vps_info += f"**Plan:** {vps.get('plan_name', 'Custom')}\n"
        vps_info += f"**Resources:** {vps['ram']} RAM | {vps['cpu']} CPU | {vps['storage']} Storage\n"
        vps_info += f"**OS:** {vps.get('os_version', 'ubuntu:22.04')}\n"
        vps_info += f"**Uptime:** {uptime_info}\n"
        vps_info += f"**CPU Usage:** {cpu_usage}\n"
        vps_info += f"**Memory:** {memory_usage}\n"
        vps_info += f"**Disk:** {disk_usage}\n"
        vps_info += f"**Created:** {vps.get('created_at', 'Unknown')[:10]}\n"
        
        embed.add_field(name=f"VPS #{i}", value=vps_info, inline=False)
    
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='claimfree')
@commands.cooldown(1, 30, commands.BucketType.user)
async def claim_free_vps(ctx):
    """Claim a free VPS based on invites/boosts"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    stats = get_user_stats(user_id)
    
    if stats['claimed_free_vps'] > 0:
        await ctx.send(embed=create_error_embed("Already Claimed", "You have already claimed a free VPS!"))
        return
    
    available_plans = []
    
    for plan in FREE_VPS_PLANS['invites']:
        if stats['invites'] >= plan['invites']:
            available_plans.append({
                'type': 'invites',
                'plan': plan,
                'required': plan['invites'],
                'current': stats['invites']
            })
    
    for plan in FREE_VPS_PLANS['boosts']:
        if stats['boosts'] >= plan['boosts']:
            available_plans.append({
                'type': 'boosts',
                'plan': plan,
                'required': plan['boosts'],
                'current': stats['boosts']
            })
    
    if not available_plans:
        embed = create_error_embed("No Eligible Plans", 
            f"You don't qualify for any free VPS plans yet.\n\n**Your Stats:**\n• Invites: {stats['invites']}\n• Boosts: {stats['boosts']}\n\nUse `{PREFIX}plans` to see requirements.")
        await ctx.send(embed=embed)
        return
    
    available_plans.sort(key=lambda x: x['plan']['ram'], reverse=True)
    best_plan = available_plans[0]
    
    embed = create_info_embed("Claim Free VPS", f"You qualify for: **{best_plan['plan']['name']}**")
    add_field(embed, "Requirements Met", 
              f"**{best_plan['type'].title()}:** {best_plan['current']}/{best_plan['required']}", False)
    add_field(embed, "Plan Resources",
              f"**RAM:** {best_plan['plan']['ram']}GB\n**CPU:** {best_plan['plan']['cpu']} cores\n**Storage:** {best_plan['plan']['disk']}GB", False)
    
    await ctx.send(embed=embed, view=ClaimFreeView(ctx, best_plan))

class ClaimFreeView(discord.ui.View):
    def __init__(self, ctx, plan_info):
        super().__init__(timeout=300)
        self.ctx = ctx
        self.plan_info = plan_info
    
    @discord.ui.button(label="Claim Now", style=discord.ButtonStyle.success, emoji="🎁")
    async def claim_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message("This claim button is not for you!", ephemeral=True)
            return
        
        stats = get_user_stats(str(self.ctx.author.id))
        if stats['claimed_free_vps'] > 0:
            await interaction.response.send_message(
                embed=create_error_embed("Already Claimed", "You have already claimed a free VPS!"),
                ephemeral=True
            )
            return
        
        admin_embed = create_info_embed("Free VPS Claim Request", 
            f"**User:** {self.ctx.author.mention}\n**Plan:** {self.plan_info['plan']['name']}\n\n**Resources:**\n• RAM: {self.plan_info['plan']['ram']}GB\n• CPU: {self.plan_info['plan']['cpu']} cores\n• Storage: {self.plan_info['plan']['disk']}GB")
        
        try:
            main_admin = await bot.fetch_user(int(MAIN_ADMIN_ID))
            await main_admin.send(embed=admin_embed)
            await interaction.response.send_message(
                embed=create_success_embed("Request Sent", "Your free VPS claim request has been sent to the admin for approval!"),
                ephemeral=True
            )
        except Exception as e:
            await interaction.response.send_message(
                embed=create_error_embed("Request Failed", "Could not send claim request. Please contact admin directly."),
                ephemeral=True
            )

# ============ VPS MANAGEMENT COMMANDS ============

class ManageView(discord.ui.View):
    def __init__(self, user_id, vps_list, is_shared=False, owner_id=None, is_admin=False, actual_index: Optional[int] = None):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.vps_list = vps_list[:]
        self.selected_index = 0 if vps_list else None
        self.is_shared = is_shared
        self.owner_id = owner_id or user_id
        self.is_admin = is_admin
        self.actual_index = actual_index
        self.indices = list(range(len(vps_list)))
        
        if self.is_shared and self.actual_index is None:
            raise ValueError("actual_index required for shared views")
        
        if len(vps_list) > 1:
            options = [
                discord.SelectOption(
                    label=f"VPS {i+1} ({v.get('plan_name', 'Custom')})",
                    description=f"Status: {v.get('status', 'unknown')}",
                    value=str(i)
                ) for i, v in enumerate(vps_list)
            ]
            self.select = discord.ui.Select(placeholder="Select a VPS to manage", options=options)
            self.select.callback = self.select_vps
            self.add_item(self.select)
        else:
            self.add_action_buttons()
    
    async def create_vps_embed(self, index):
        vps = self.vps_list[index]
        status = vps.get('status', 'unknown')
        suspended = vps.get('suspended', False)
        whitelisted = vps.get('whitelisted', False)
        status_color = 0x00ff88 if status == 'running' and not suspended else 0xffaa00 if suspended else 0xff3366
        container_name = vps['container_name']
        
        lxc_status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        
        status_text = f"{lxc_status.upper()}"
        if suspended:
            status_text += " (SUSPENDED)"
        if whitelisted:
            status_text += " (WHITELISTED)"
        
        owner_text = ""
        if self.is_admin and self.owner_id != self.user_id:
            try:
                owner_user = await bot.fetch_user(int(self.owner_id))
                owner_text = f"\n**Owner:** {owner_user.mention}"
            except:
                owner_text = f"\n**Owner ID:** {self.owner_id}"
        
        embed = discord.Embed(
            title=f"🖥️ VPS Management",
            description=f"Managing VPS #{index + 1}: `{container_name}`{owner_text}",
            color=status_color
        )
        
        resource_info = f"**Plan:** {vps.get('plan_name', 'Custom')}\n"
        resource_info += f"**Status:** {status_text}\n"
        resource_info += f"**RAM:** {vps['ram']}\n"
        resource_info += f"**CPU:** {vps['cpu']} Cores\n"
        resource_info += f"**Storage:** {vps['storage']}\n"
        resource_info += f"**OS:** {vps.get('os_version', 'ubuntu:22.04')}\n"
        resource_info += f"**Uptime:** {uptime}"
        
        embed.add_field(name="⌯⌲ Resources", value=resource_info, inline=False)
        
        if suspended:
            embed.add_field(name="⌯⌲ Suspended", value="This VPS is suspended. Contact an admin to unsuspend.", inline=False)
        if whitelisted:
            embed.add_field(name="⌯⌲ Whitelisted", value="This VPS is exempt from auto-suspension.", inline=False)
        
        live_stats = f"**CPU Usage:** {cpu_usage}\n**Memory:** {memory_usage}\n**Disk:** {disk_usage}"
        embed.add_field(name="⌯⌲ Live Usage", value=live_stats, inline=False)
        embed.add_field(name="⌯⌲ Controls", value="Use the buttons below to manage your VPS", inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        
        return embed
    
    def add_action_buttons(self):
        if not self.is_shared and not self.is_admin:
            reinstall_button = discord.ui.Button(label="🔄 Reinstall", style=discord.ButtonStyle.danger)
            reinstall_button.callback = lambda inter: self.action_callback(inter, 'reinstall')
            self.add_item(reinstall_button)
        
        start_button = discord.ui.Button(label="▶ Start", style=discord.ButtonStyle.success)
        start_button.callback = lambda inter: self.action_callback(inter, 'start')
        
        stop_button = discord.ui.Button(label="⏹ Stop", style=discord.ButtonStyle.secondary)
        stop_button.callback = lambda inter: self.action_callback(inter, 'stop')
        
        ssh_button = discord.ui.Button(label="🔑 SSH", style=discord.ButtonStyle.primary)
        ssh_button.callback = lambda inter: self.action_callback(inter, 'ssh')
        
        sshx_button = discord.ui.Button(label="🔗 SSHX", style=discord.ButtonStyle.success)
        sshx_button.callback = lambda inter: self.action_callback(inter, 'sshx')
        
        stats_button = discord.ui.Button(label="📊 Stats", style=discord.ButtonStyle.secondary)
        stats_button.callback = lambda inter: self.action_callback(inter, 'stats')
        
        self.add_item(start_button)
        self.add_item(stop_button)
        self.add_item(ssh_button)
        self.add_item(sshx_button)
        self.add_item(stats_button)
    
    async def select_vps(self, interaction: discord.Interaction):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your VPS!"), ephemeral=True)
            return
        
        self.selected_index = int(self.select.values[0])
        new_embed = await self.create_vps_embed(self.selected_index)
        self.clear_items()
        self.add_action_buttons()
        await interaction.response.edit_message(embed=new_embed, view=self)
    
    async def action_callback(self, interaction: discord.Interaction, action: str):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your VPS!"), ephemeral=True)
            return
        
        if self.selected_index is None and len(self.vps_list) == 1:
            self.selected_index = 0
        
        if self.selected_index is None:
            await interaction.response.send_message(embed=create_error_embed("No VPS Selected", "Please select a VPS first."), ephemeral=True)
            return
        
        actual_idx = self.actual_index if self.is_shared else self.indices[self.selected_index]
        target_vps = vps_data[self.owner_id][actual_idx]
        suspended = target_vps.get('suspended', False)
        
        if suspended and not self.is_admin and action not in ['stats']:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This VPS is suspended. Contact an admin to unsuspend."), ephemeral=True)
            return
        
        container_name = target_vps["container_name"]
        
        if action == 'stats':
            status = await get_container_status(container_name)
            cpu_usage = await get_container_cpu(container_name)
            memory_usage = await get_container_memory(container_name)
            disk_usage = await get_container_disk(container_name)
            uptime = await get_container_uptime(container_name)
            
            stats_embed = create_info_embed("Live Statistics", f"Real-time stats for `{container_name}`")
            add_field(stats_embed, "Status", f"`{status.upper()}`", True)
            add_field(stats_embed, "CPU", cpu_usage, True)
            add_field(stats_embed, "Memory", memory_usage, True)
            add_field(stats_embed, "Disk", disk_usage, True)
            add_field(stats_embed, "Uptime", uptime, True)
            
            await interaction.response.send_message(embed=stats_embed, ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
        if action == 'start':
            try:
                await execute_lxc(f"lxc start {container_name}")
                target_vps["status"] = "running"
                target_vps["suspended"] = False
                save_vps_data()
                await apply_internal_permissions(container_name)
                await interaction.followup.send(embed=create_success_embed("VPS Started", f"VPS `{container_name}` is now running!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)), ephemeral=True)
        
        elif action == 'stop':
            try:
                await execute_lxc(f"lxc stop {container_name}", timeout=120)
                target_vps["status"] = "stopped"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Stopped", f"VPS `{container_name}` has been stopped!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Stop Failed", str(e)), ephemeral=True)
        
        elif action == 'ssh':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Cannot access suspended VPS."), ephemeral=True)
                return
            
            await interaction.followup.send(embed=create_info_embed("SSH Access", "Generating SSH connection..."), ephemeral=True)
            
            try:
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "which", "tmate",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()
                
                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSH", "Installing tmate..."), ephemeral=True)
                    await execute_lxc(f"lxc exec {container_name} -- apt-get update -y")
                    await execute_lxc(f"lxc exec {container_name} -- apt-get install tmate -y")
                    await interaction.followup.send(embed=create_success_embed("Installed", "SSH service installed!"), ephemeral=True)
                
                session_name = f"{BOT_NAME.lower()}-session-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                await execute_lxc(f"lxc exec {container_name} -- tmate -S /tmp/{session_name}.sock new-session -d")
                await asyncio.sleep(3)
                
                ssh_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "tmate", "-S", f"/tmp/{session_name}.sock", "display", "-p", "#{tmate_ssh}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await ssh_proc.communicate()
                ssh_url = stdout.decode().strip() if stdout else None
                
                if ssh_url:
                    try:
                        ssh_embed = discord.Embed(
                            title=f"🔑 {BOT_NAME} - SSH Access",
                            description=f"SSH connection for VPS `{container_name}`:",
                            color=0x00ff88
                        )
                        ssh_embed.add_field(name="⌯⌲ Command", value=f"```{ssh_url}```", inline=False)
                        ssh_embed.add_field(name="⌯⌲ Security", value="This link is temporary. Do not share it.", inline=False)
                        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                            ssh_embed.set_thumbnail(url=THUMBNAIL)
                        if BANNER and BANNER.startswith(('http://', 'https://')):
                            ssh_embed.set_image(url=BANNER)
                        ssh_embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for SSH link!"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", "Enable DMs to receive SSH link!"), ephemeral=True)
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    await interaction.followup.send(embed=create_error_embed("SSH Failed", error_msg), ephemeral=True)
            
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSH Error", str(e)), ephemeral=True)
        
        elif action == 'sshx':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Cannot access suspended VPS."), ephemeral=True)
                return
            
            await interaction.followup.send(embed=create_info_embed("🔗 SSHX Access", f"Generating web-based SSH connection for VPS `{container_name}`..."), ephemeral=True)
            
            try:
                # Update package list and install curl if needed
                await execute_lxc(f"lxc exec {container_name} -- bash -c 'apt-get update -y'", timeout=60)
                await execute_lxc(f"lxc exec {container_name} -- bash -c 'apt-get install curl -y'", timeout=60)
                
                # Install and run SSHX
                await execute_lxc(f"lxc exec {container_name} -- bash -c 'curl -sSf https://sshx.io/get | sh'", timeout=30)
                
                # Wait a moment for SSHX to start
                await asyncio.sleep(5)
                
                # Get the SSHX connection URL
                sshx_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "bash", "-c", "sshx | grep -o 'https://sshx.io/[a-zA-Z0-9]*' | head -1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await sshx_proc.communicate()
                sshx_url = stdout.decode().strip() if stdout else None
                
                if sshx_url:
                    try:
                        # Create the exact embed as shown in the screenshot
                        sshx_embed = discord.Embed(
                            title=f"{BOT_NAME} • SSHX Access",
                            description=f"Web SSH connection for VPS `{container_name}`:",
                            color=0x00ff88
                        )
                        
                        # Add clickable link
                        sshx_embed.add_field(
                            name="🔗 Link", 
                            value=f"[Click to Open Terminal]({sshx_url})", 
                            inline=False
                        )
                        
                        # Add security warning
                        sshx_embed.add_field(
                            name="⚠️ Security", 
                            value="This link grants direct root access. Do not share it.", 
                            inline=False
                        )
                        
                        # Add thumbnail and banner
                        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                            sshx_embed.set_thumbnail(url=THUMBNAIL)
                        if BANNER and BANNER.startswith(('http://', 'https://')):
                            sshx_embed.set_image(url=BANNER)
                        
                        # Add footer with timestamp
                        sshx_embed.set_footer(
                            text=f"Powered by {BOT_NAME} • Premium VPS Management • {datetime.now().strftime('%d-%m-%Y %H:%M')}"
                        )
                        
                        # Send via DM
                        await interaction.user.send(embed=sshx_embed)
                        
                        # Confirm in channel
                        await interaction.followup.send(
                            embed=create_success_embed("✅ SSHX Ready", "SSHX web terminal link has been sent to your DMs!"), 
                            ephemeral=True
                        )
                    except discord.Forbidden:
                        await interaction.followup.send(
                            embed=create_error_embed("❌ DM Failed", "Please enable DMs to receive the SSHX link!"), 
                            ephemeral=True
                        )
                else:
                    error_msg = stderr.decode().strip() if stderr else "Could not generate SSHX link"
                    await interaction.followup.send(
                        embed=create_error_embed("❌ SSHX Failed", f"Error: {error_msg}"), 
                        ephemeral=True
                    )
            
            except Exception as e:
                await interaction.followup.send(
                    embed=create_error_embed("❌ SSHX Error", f"Error: {str(e)}"), 
                    ephemeral=True
                )
        
        elif action == 'reinstall':
            if self.is_shared or self.is_admin:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Only the VPS owner can reinstall!"), ephemeral=True)
                return
            
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Cannot Reinstall", "Unsuspend the VPS first."), ephemeral=True)
                return
            
            await interaction.followup.send(embed=create_info_embed("Reinstall", "This feature is coming soon!"), ephemeral=True)
        
        if self.selected_index is not None:
            new_embed = await self.create_vps_embed(self.selected_index)
            await interaction.edit_original_response(embed=new_embed, view=self)

@bot.command(name='manage')
@commands.cooldown(1, 5, commands.BucketType.user)
async def manage_vps(ctx, user: discord.Member = None):
    """Manage your VPS"""
    if not await maintenance_check(ctx):
        return
    
    if user:
        user_id_check = str(ctx.author.id)
        if user_id_check != str(MAIN_ADMIN_ID) and user_id_check not in admin_data.get("admins", []):
            await ctx.send(embed=create_error_embed("Access Denied", "Only admins can manage other users' VPS."))
            return
        
        user_id = str(user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            embed = discord.Embed(
                title="☁️ No VPS Found",
                description=f"{user.mention} doesn't have any VPS.",
                color=0xff3366
            )
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await ctx.send(embed=embed)
            return
        
        view = ManageView(str(ctx.author.id), vps_list, is_admin=True, owner_id=user_id)
        embed = await view.create_vps_embed(0)
        await ctx.send(embed=embed, view=view)
    
    else:
        user_id = str(ctx.author.id)
        vps_list = vps_data.get(user_id, [])
        
        if not vps_list:
            embed = discord.Embed(
                title="☁️ No VPS Found",
                description="You don't have any VPS. Do invites or boosts to get one.",
                color=0xff3366
            )
            embed.add_field(
                name="⌯⌲ Quick Actions",
                value=f"`.plans`",
                inline=False
            )
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await ctx.send(embed=embed)
            return
        
        view = ManageView(user_id, vps_list)
        embed = await view.create_vps_embed(0)
        await ctx.send(embed=embed, view=view)

@bot.command(name='share-user')
@commands.cooldown(1, 3, commands.BucketType.user)
async def share_user(ctx, shared_user: discord.Member, vps_number: int):
    """Share VPS access with another user"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a VPS."))
        return
    
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    
    if shared_user_id in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Already Shared", f"{shared_user.mention} already has access to this VPS!"))
        return
    
    vps["shared_with"].append(shared_user_id)
    save_vps_data()
    
    embed = discord.Embed(
        title="✅ VPS Shared",
        description=f"VPS #{vps_number} shared with {shared_user.mention}!",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='share-ruser')
@commands.cooldown(1, 3, commands.BucketType.user)
async def revoke_share(ctx, shared_user: discord.Member, vps_number: int):
    """Revoke VPS access from another user"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a VPS."))
        return
    
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    
    if shared_user_id not in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Not Shared", f"{shared_user.mention} doesn't have access to this VPS!"))
        return
    
    vps["shared_with"].remove(shared_user_id)
    save_vps_data()
    
    embed = discord.Embed(
        title="✅ Access Revoked",
        description=f"Access to VPS #{vps_number} revoked from {shared_user.mention}!",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='manage-shared')
@commands.cooldown(1, 3, commands.BucketType.user)
async def manage_shared_vps(ctx, owner: discord.Member, vps_number: int):
    """Manage a VPS that has been shared with you"""
    if not await maintenance_check(ctx):
        return
    
    owner_id = str(owner.id)
    user_id = str(ctx.author.id)
    
    if owner_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[owner_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or owner doesn't have a VPS."))
        return
    
    vps = vps_data[owner_id][vps_number - 1]
    if user_id not in vps.get("shared_with", []):
        await ctx.send(embed=create_error_embed("Access Denied", "You do not have access to this VPS."))
        return
    
    view = ManageView(user_id, [vps], is_shared=True, owner_id=owner_id, actual_index=vps_number - 1)
    embed = await view.create_vps_embed(0)
    await ctx.send(embed=embed, view=view)

@bot.command(name='vpsinfo')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def vps_info(ctx, container_name: str):
    """VPS information"""
    if not container_name:
        await ctx.send(embed=create_error_embed("Usage", f"Usage: {PREFIX}vpsinfo <container_name>"))
        return
    
    found_vps = None
    found_user = None
    user_id = None
    
    for uid, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                try:
                    found_user = await bot.fetch_user(int(uid))
                except:
                    found_user = None
                break
        if found_vps:
            break
    
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No VPS found with container name: `{container_name}`"))
        return
    
    status = await get_container_status(container_name)
    cpu = await get_container_cpu(container_name)
    memory = await get_container_memory(container_name)
    disk = await get_container_disk(container_name)
    uptime = await get_container_uptime(container_name)
    
    embed = discord.Embed(
        title=f"🖥️ VPS Information - {container_name}",
        description=f"Details for VPS",
        color=0x1a1a1a
    )
    
    embed.add_field(name="⌯⌲ Owner", value=found_user.mention if found_user else f"ID: {user_id}", inline=True)
    embed.add_field(name="⌯⌲ Status", value=status.upper(), inline=True)
    embed.add_field(name="⌯⌲ Plan", value=found_vps.get('plan_name', 'Custom'), inline=True)
    
    resources = f"**RAM:** {found_vps['ram']}\n"
    resources += f"**CPU:** {found_vps['cpu']} Cores\n"
    resources += f"**Storage:** {found_vps['storage']}\n"
    resources += f"**OS:** {found_vps.get('os_version', 'ubuntu:22.04')}"
    embed.add_field(name="⌯⌲ Allocated Resources", value=resources, inline=False)
    
    live_stats = f"**CPU Usage:** {cpu}\n"
    live_stats += f"**Memory:** {memory}\n"
    live_stats += f"**Disk:** {disk}\n"
    live_stats += f"**Uptime:** {uptime}"
    embed.add_field(name="⌯⌲ Live Statistics", value=live_stats, inline=False)
    
    if found_vps.get('suspended', False):
        embed.add_field(name="⌯⌲ Suspended", value=f"Reason: {found_vps.get('suspended_reason', 'No reason')}", inline=False)
    
    if found_vps.get('whitelisted', False):
        embed.add_field(name="⌯⌲ Whitelisted", value="Exempt from auto-suspension", inline=False)
    
    created = found_vps.get('created_at', 'Unknown')[:19].replace('T', ' ')
    embed.add_field(name="⌯⌲ Created", value=created, inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    
    await ctx.send(embed=embed)

@bot.command(name='vps-stats')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def vps_stats(ctx, container_name: str):
    """VPS stats"""
    cpu = await get_container_cpu(container_name)
    memory = await get_container_memory(container_name)
    disk = await get_container_disk(container_name)
    uptime = await get_container_uptime(container_name)
    
    embed = discord.Embed(
        title=f"📊 VPS Stats - {container_name}",
        description=f"**CPU Usage:** {cpu}\n**Memory:** {memory}\n**Disk:** {disk}\n**Uptime:** {uptime}",
        color=0x00ccff
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='restart-vps')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def restart_vps(ctx, container_name: str):
    """Restart VPS"""
    await ctx.send(embed=create_info_embed("Restarting VPS", f"Restarting VPS `{container_name}`..."))
    
    try:
        await execute_lxc(f"lxc restart {container_name}")
        
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break
        
        await apply_internal_permissions(container_name)
        
        embed = discord.Embed(
            title="✅ VPS Restarted",
            description=f"VPS `{container_name}` has been restarted successfully!",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    
    except Exception as e:
        await ctx.send(embed=create_error_embed("Restart Failed", f"Error: {str(e)}"))

@bot.command(name='clone-vps')
@is_admin()
@commands.cooldown(1, 30, commands.BucketType.user)
async def clone_vps(ctx, container_name: str, new_name: str = None):
    """Clone VPS"""
    if not new_name:
        new_name = f"{container_name}-clone-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    await ctx.send(embed=create_info_embed("Cloning VPS", f"Cloning `{container_name}` to `{new_name}`..."))
    
    try:
        await execute_lxc(f"lxc copy {container_name} {new_name}")
        embed = discord.Embed(
            title="✅ VPS Cloned",
            description=f"VPS `{container_name}` cloned to `{new_name}`",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Clone Failed", f"Error: {str(e)}"))

@bot.command(name='snapshot')
@is_admin()
@commands.cooldown(1, 30, commands.BucketType.user)
async def create_snapshot(ctx, container_name: str, snap_name: str = None):
    """Create snapshot"""
    if not snap_name:
        snap_name = f"snap-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    await ctx.send(embed=create_info_embed("Creating Snapshot", f"Creating snapshot `{snap_name}` for `{container_name}`..."))
    
    try:
        await execute_lxc(f"lxc snapshot {container_name} {snap_name}")
        embed = discord.Embed(
            title="✅ Snapshot Created",
            description=f"Snapshot `{snap_name}` created for `{container_name}`",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Snapshot Failed", f"Error: {str(e)}"))

@bot.command(name='restore-backup')
@is_admin()
@commands.cooldown(1, 30, commands.BucketType.user)
async def restore_backup(ctx, container_name: str, snap_name: str):
    """Restore VPS Data"""
    await ctx.send(embed=create_info_embed("Restoring Backup", f"Restoring `{container_name}` from snapshot `{snap_name}`..."))
    
    try:
        await execute_lxc(f"lxc restore {container_name} {snap_name}")
        embed = discord.Embed(
            title="✅ Backup Restored",
            description=f"VPS `{container_name}` restored from snapshot `{snap_name}`",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Restore Failed", f"Error: {str(e)}"))

# ============ BOT SYSTEM COMMANDS ============

@bot.command(name='addinv')
@is_admin()
@commands.cooldown(1, 2, commands.BucketType.user)
async def add_invites(ctx, user: discord.Member, amount: int):
    """Add invites to user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be positive."))
        return
    
    update_user_stats(str(user.id), invites=amount)
    stats = get_user_stats(str(user.id))
    
    embed = discord.Embed(
        title="✅ Invites Added",
        description=f"Added **{amount}** invites to {user.mention}",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Stats", 
                  value=f"**Total Invites:** {stats['invites']}\n**Boosts:** {stats['boosts']}\n**Credits:** {stats.get('credits', 0)}", 
                  inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='removeinv')
@is_admin()
@commands.cooldown(1, 2, commands.BucketType.user)
async def remove_invites(ctx, user: discord.Member, amount: int):
    """Remove invites from user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be positive."))
        return
    
    stats = get_user_stats(str(user.id))
    if stats['invites'] < amount:
        amount = stats['invites']
    
    update_user_stats(str(user.id), invites=-amount)
    new_stats = get_user_stats(str(user.id))
    
    embed = discord.Embed(
        title="✅ Invites Removed",
        description=f"Removed **{amount}** invites from {user.mention}",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Stats", 
                  value=f"**Total Invites:** {new_stats['invites']}\n**Boosts:** {new_stats['boosts']}\n**Credits:** {new_stats.get('credits', 0)}", 
                  inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='addboost')
@is_admin()
@commands.cooldown(1, 2, commands.BucketType.user)
async def add_boosts(ctx, user: discord.Member, amount: int):
    """Add boosts to user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be positive."))
        return
    
    update_user_stats(str(user.id), boosts=amount)
    stats = get_user_stats(str(user.id))
    
    embed = discord.Embed(
        title="✅ Boosts Added",
        description=f"Added **{amount}** boosts to {user.mention}",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Stats", 
                  value=f"**Invites:** {stats['invites']}\n**Total Boosts:** {stats['boosts']}\n**Credits:** {stats.get('credits', 0)}", 
                  inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='removeboost')
@is_admin()
@commands.cooldown(1, 2, commands.BucketType.user)
async def remove_boosts(ctx, user: discord.Member, amount: int):
    """Remove boosts from user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be positive."))
        return
    
    stats = get_user_stats(str(user.id))
    if stats['boosts'] < amount:
        amount = stats['boosts']
    
    update_user_stats(str(user.id), boosts=-amount)
    new_stats = get_user_stats(str(user.id))
    
    embed = discord.Embed(
        title="✅ Boosts Removed",
        description=f"Removed **{amount}** boosts from {user.mention}",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Stats", 
                  value=f"**Invites:** {new_stats['invites']}\n**Total Boosts:** {new_stats['boosts']}\n**Credits:** {new_stats.get('credits', 0)}", 
                  inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='credits')
@is_admin()
@commands.cooldown(1, 2, commands.BucketType.user)
async def add_credits(ctx, user: discord.Member, amount: int):
    """Add credits to user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be positive."))
        return
    
    update_user_stats(str(user.id), credits=amount)
    stats = get_user_stats(str(user.id))
    
    embed = discord.Embed(
        title="✅ Credits Added",
        description=f"Added **{amount}** credits to {user.mention}",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Stats", 
                  value=f"**Invites:** {stats['invites']}\n**Boosts:** {stats['boosts']}\n**Total Credits:** {stats.get('credits', 0)}", 
                  inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='dailycredit')
@commands.cooldown(1, 10, commands.BucketType.user)
async def daily_credit(ctx):
    """Claim daily credits"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    stats = get_user_stats(user_id)
    
    now = datetime.now()
    
    if stats.get('last_daily'):
        last_daily = datetime.fromisoformat(stats['last_daily'])
        if now.date() == last_daily.date():
            next_claim = (last_daily + timedelta(days=1)).strftime('%Y-%m-%d')
            embed = create_error_embed("Already Claimed", f"You have already claimed your daily credits today!\nNext claim available: **{next_claim}**")
            await ctx.send(embed=embed)
            return
    
    update_user_stats(user_id, credits=DAILY_CREDIT_AMOUNT, last_daily=now.isoformat())
    new_stats = get_user_stats(user_id)
    
    embed = discord.Embed(
        title="💰 Daily Credits Claimed",
        description=f"You received **{DAILY_CREDIT_AMOUNT}** credits!",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Current Balance", value=f"**{new_stats.get('credits', 0)}** credits", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='edit-plans')
@is_main_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def edit_plans(ctx):
    """Edit VPS plans"""
    embed = create_info_embed("📋 Plan Editor", "Select a plan to edit from the dropdown below.")
    view = PlanEditView(ctx)
    await ctx.send(embed=embed, view=view)

class PlanEditView(discord.ui.View):
    def __init__(self, ctx):
        super().__init__(timeout=300)
        self.ctx = ctx
        
        self.select = discord.ui.Select(
            placeholder="Select a plan to edit...",
            options=[
                discord.SelectOption(label="📋 Free Tier I (10 Invites)", value="invites_0", description="12GB RAM, 4 CPU, 100GB Disk"),
                discord.SelectOption(label="📋 Free Tier II (20 Invites)", value="invites_1", description="24GB RAM, 6 CPU, 250GB Disk"),
                discord.SelectOption(label="📋 Free Tier III (28 Invites)", value="invites_2", description="32GB RAM, 8 CPU, 300GB Disk"),
                discord.SelectOption(label="⚡ Boost Reward I (1 Boost)", value="boosts_0", description="24GB RAM, 6 CPU, 250GB Disk"),
                discord.SelectOption(label="⚡ Boost Reward II (2 Boosts)", value="boosts_1", description="32GB RAM, 8 CPU, 300GB Disk"),
            ]
        )
        self.select.callback = self.select_callback
        self.add_item(self.select)
        
        self.add_item(discord.ui.Button(label="❌ Close", style=discord.ButtonStyle.danger, custom_id="close", row=1))
    
    async def select_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.ctx.author.id:
            await interaction.response.send_message("This menu is not for you!", ephemeral=True)
            return
        
        value = self.select.values[0]
        category, index = value.split('_')
        index = int(index)
        
        plan = FREE_VPS_PLANS[category][index]
        
        embed = discord.Embed(
            title=f"✏️ Editing Plan: {plan['name']}",
            description=f"Current configuration:",
            color=0x00ccff
        )
        embed.add_field(name="RAM", value=f"{plan['ram']} GB", inline=True)
        embed.add_field(name="CPU", value=f"{plan['cpu']} Cores", inline=True)
        embed.add_field(name="Disk", value=f"{plan['disk']} GB", inline=True)
        embed.add_field(name="Requirement", value=f"{plan.get('invites', plan.get('boosts'))} {'Invites' if 'invites' in plan else 'Boosts'}", inline=False)
        
        view = PlanEditActionView(self.ctx, category, index, plan)
        await interaction.response.edit_message(embed=embed, view=view)
    
    @discord.ui.button(label="❌ Close", style=discord.ButtonStyle.danger, row=1)
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.ctx.author.id:
            await interaction.response.send_message("This menu is not for you!", ephemeral=True)
            return
        
        embed = create_info_embed("Plan Editor Closed", "No changes were made.")
        await interaction.response.edit_message(embed=embed, view=None)

class PlanEditActionView(discord.ui.View):
    def __init__(self, ctx, category, index, plan):
        super().__init__(timeout=300)
        self.ctx = ctx
        self.category = category
        self.index = index
        self.plan = plan
        
        self.add_item(discord.ui.Button(label="📝 Edit RAM", style=discord.ButtonStyle.primary, custom_id="edit_ram", row=0))
        self.add_item(discord.ui.Button(label="📝 Edit CPU", style=discord.ButtonStyle.primary, custom_id="edit_cpu", row=0))
        self.add_item(discord.ui.Button(label="📝 Edit Disk", style=discord.ButtonStyle.primary, custom_id="edit_disk", row=0))
        self.add_item(discord.ui.Button(label="📝 Edit Requirement", style=discord.ButtonStyle.primary, custom_id="edit_req", row=1))
        self.add_item(discord.ui.Button(label="💾 Save Changes", style=discord.ButtonStyle.success, custom_id="save", row=2))
        self.add_item(discord.ui.Button(label="⬅️ Back", style=discord.ButtonStyle.secondary, custom_id="back", row=2))
        self.add_item(discord.ui.Button(label="❌ Cancel", style=discord.ButtonStyle.danger, custom_id="cancel", row=2))
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.ctx.author.id:
            await interaction.response.send_message("This menu is not for you!", ephemeral=True)
            return False
        return True
    
    @discord.ui.button(label="📝 Edit RAM", style=discord.ButtonStyle.primary, custom_id="edit_ram", row=0)
    async def edit_ram(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = EditPlanModal(self, "ram", f"Enter new RAM value (current: {self.plan['ram']} GB)")
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="📝 Edit CPU", style=discord.ButtonStyle.primary, custom_id="edit_cpu", row=0)
    async def edit_cpu(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = EditPlanModal(self, "cpu", f"Enter new CPU core count (current: {self.plan['cpu']})")
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="📝 Edit Disk", style=discord.ButtonStyle.primary, custom_id="edit_disk", row=0)
    async def edit_disk(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = EditPlanModal(self, "disk", f"Enter new Disk size in GB (current: {self.plan['disk']} GB)")
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="📝 Edit Requirement", style=discord.ButtonStyle.primary, custom_id="edit_req", row=1)
    async def edit_req(self, interaction: discord.Interaction, button: discord.ui.Button):
        req_type = "invites" if 'invites' in self.plan else "boosts"
        current = self.plan.get('invites', self.plan.get('boosts'))
        modal = EditPlanModal(self, "req", f"Enter new {req_type} requirement (current: {current})")
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="💾 Save Changes", style=discord.ButtonStyle.success, custom_id="save", row=2)
    async def save_changes(self, interaction: discord.Interaction, button: discord.ui.Button):
        FREE_VPS_PLANS[self.category][self.index] = self.plan
        
        embed = discord.Embed(
            title="✅ Plan Updated",
            description=f"**{self.plan['name']}** has been updated successfully!",
            color=0x00ff88
        )
        embed.add_field(name="⌯⌲ New Configuration", 
                       value=f"**RAM:** {self.plan['ram']} GB\n**CPU:** {self.plan['cpu']} Cores\n**Disk:** {self.plan['disk']} GB\n**Requirement:** {self.plan.get('invites', self.plan.get('boosts'))} {'Invites' if 'invites' in self.plan else 'Boosts'}", 
                       inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await interaction.response.edit_message(embed=embed, view=None)
    
    @discord.ui.button(label="⬅️ Back", style=discord.ButtonStyle.secondary, custom_id="back", row=2)
    async def go_back(self, interaction: discord.Interaction, button: discord.ui.Button):
        view = PlanEditView(self.ctx)
        embed = create_info_embed("📋 Plan Editor", "Select a plan to edit from the dropdown below.")
        await interaction.response.edit_message(embed=embed, view=view)
    
    @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.danger, custom_id="cancel", row=2)
    async def cancel_edit(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = create_info_embed("Plan Editor Closed", "No changes were saved.")
        await interaction.response.edit_message(embed=embed, view=None)

class EditPlanModal(discord.ui.Modal, title="Edit Plan Value"):
    def __init__(self, parent_view, field, prompt):
        super().__init__()
        self.parent_view = parent_view
        self.field = field
        
        self.value_input = discord.ui.TextInput(
            label=prompt,
            placeholder="Enter new value...",
            required=True,
            min_length=1,
            max_length=3
        )
        self.add_item(self.value_input)
    
    async def on_submit(self, interaction: discord.Interaction):
        try:
            new_value = int(self.value_input.value)
            if new_value <= 0:
                await interaction.response.send_message("Value must be positive!", ephemeral=True)
                return
            
            if self.field == "ram":
                self.parent_view.plan['ram'] = new_value
            elif self.field == "cpu":
                self.parent_view.plan['cpu'] = new_value
            elif self.field == "disk":
                self.parent_view.plan['disk'] = new_value
            elif self.field == "req":
                if 'invites' in self.parent_view.plan:
                    self.parent_view.plan['invites'] = new_value
                else:
                    self.parent_view.plan['boosts'] = new_value
            
            embed = discord.Embed(
                title=f"✏️ Editing Plan: {self.parent_view.plan['name']}",
                description=f"Updated configuration:",
                color=0x00ccff
            )
            embed.add_field(name="RAM", value=f"{self.parent_view.plan['ram']} GB", inline=True)
            embed.add_field(name="CPU", value=f"{self.parent_view.plan['cpu']} Cores", inline=True)
            embed.add_field(name="Disk", value=f"{self.parent_view.plan['disk']} GB", inline=True)
            embed.add_field(name="Requirement", value=f"{self.parent_view.plan.get('invites', self.parent_view.plan.get('boosts'))} {'Invites' if 'invites' in self.parent_view.plan else 'Boosts'}", inline=False)
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            
            await interaction.response.edit_message(embed=embed, view=self.parent_view)
            
        except ValueError:
            await interaction.response.send_message("Please enter a valid number!", ephemeral=True)

# ============ ADMIN COMMANDS ============

@bot.command(name='admin-add')
@is_main_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def admin_add(ctx, user: discord.Member):
    """Add admin"""
    user_id = str(user.id)
    
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Already Admin", "This user is already the main admin!"))
        return
    
    if user_id in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Already Admin", f"{user.mention} is already an admin!"))
        return
    
    admin_data["admins"].append(user_id)
    save_admin_data()
    
    embed = discord.Embed(
        title="✅ Admin Added",
        description=f"{user.mention} has been added as an admin!",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='admin-remove')
@is_main_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def admin_remove(ctx, user: discord.Member):
    """Remove admin"""
    user_id = str(user.id)
    
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Cannot Remove", "You cannot remove the main admin!"))
        return
    
    if user_id not in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Not Admin", f"{user.mention} is not an admin!"))
        return
    
    admin_data["admins"].remove(user_id)
    save_admin_data()
    
    embed = discord.Embed(
        title="✅ Admin Removed",
        description=f"{user.mention} has been removed as an admin!",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='admin-list')
@is_main_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def admin_list(ctx):
    """List admins"""
    embed = discord.Embed(
        title="🛡️ Admin List",
        description="Current administrators of the system",
        color=0x00ccff
    )
    
    try:
        main_admin = await bot.fetch_user(int(MAIN_ADMIN_ID))
        embed.add_field(name="⌯⌲ Main Admin", value=f"{main_admin.mention}", inline=False)
    except:
        embed.add_field(name="⌯⌲ Main Admin", value=f"User ID: {MAIN_ADMIN_ID}", inline=False)
    
    if admin_data['admins']:
        admin_text = []
        for admin_id in admin_data['admins']:
            try:
                admin_user = await bot.fetch_user(int(admin_id))
                admin_text.append(f"• {admin_user.mention}")
            except:
                admin_text.append(f"• User ID: {admin_id}")
        
        embed.add_field(name="⌯⌲ Admins", value="\n".join(admin_text), inline=False)
    else:
        embed.add_field(name="⌯⌲ Admins", value="No additional admins", inline=False)
    
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='create')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def create_vps(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    """Create VPS with OS selection"""
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."))
        return
    
    embed = create_info_embed("VPS Creation", 
        f"Creating VPS for {user.mention}\n"
        f"**RAM:** {ram}GB\n"
        f"**CPU:** {cpu} Cores\n"
        f"**Disk:** {disk}GB\n\n"
        f"Select OS below.")
    
    view = OSSelectView(ram, cpu, disk, user, ctx)
    await ctx.send(embed=embed, view=view)

class OSSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.selected_os = None
        self.select = discord.ui.Select(
            placeholder="Select an OS for the VPS",
            options=[discord.SelectOption(label=o["label"], value=o["value"]) for o in OS_OPTIONS]
        )
        self.select.callback = self.select_os
        self.add_item(self.select)
        self.add_item(discord.ui.Button(label="❌ Cancel", style=discord.ButtonStyle.danger, custom_id="cancel", row=1))
    
    async def select_os(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the command author can select."), ephemeral=True)
            return
        
        self.selected_os = self.select.values[0]
        await interaction.response.defer()
        
        confirm_view = discord.ui.View()
        confirm_button = discord.ui.Button(label="✅ Confirm", style=discord.ButtonStyle.success, custom_id="confirm")
        cancel_button = discord.ui.Button(label="❌ Cancel", style=discord.ButtonStyle.danger, custom_id="cancel")
        
        async def confirm_callback(confirm_interaction):
            await self.create_vps(confirm_interaction, self.selected_os)
        
        async def cancel_callback(cancel_interaction):
            await cancel_interaction.response.edit_message(embed=create_info_embed("Cancelled", "VPS creation cancelled."), view=None)
        
        confirm_button.callback = confirm_callback
        cancel_button.callback = cancel_callback
        
        confirm_view.add_item(confirm_button)
        confirm_view.add_item(cancel_button)
        
        embed = create_info_embed("Confirm VPS Creation", 
            f"**User:** {self.user.mention}\n"
            f"**OS:** {self.selected_os}\n"
            f"**RAM:** {self.ram}GB\n"
            f"**CPU:** {self.cpu} Cores\n"
            f"**Disk:** {self.disk}GB\n\n"
            f"Please confirm to proceed.")
        
        await interaction.edit_original_response(embed=embed, view=confirm_view)
    
    async def create_vps(self, interaction: discord.Interaction, os_version: str):
        await interaction.response.defer()
        
        creating_embed = create_info_embed("Creating VPS", f"Deploying {os_version} VPS for {self.user.mention}...")
        await interaction.edit_original_response(embed=creating_embed, view=None)
        
        user_id = str(self.user.id)
        if user_id not in vps_data:
            vps_data[user_id] = []
        
        vps_count = len(vps_data[user_id]) + 1
        container_name = f"{BOT_NAME.lower()}-vps-{user_id}-{vps_count}"
        ram_mb = self.ram * 1024
        
        try:
            await execute_lxc(f"lxc init {os_version} {container_name} -s {DEFAULT_STORAGE_POOL}")
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            await execute_lxc(f"lxc config set {container_name} limits.cpu {self.cpu}")
            await execute_lxc(f"lxc config device set {container_name} root size={self.disk}GB")
            await apply_lxc_config(container_name)
            await execute_lxc(f"lxc start {container_name}")
            await apply_internal_permissions(container_name)
            
            config_str = f"{self.ram}GB RAM / {self.cpu} CPU / {self.disk}GB Disk"
            vps_info = {
                "container_name": container_name,
                "plan_name": "Custom",
                "ram": f"{self.ram}GB",
                "cpu": str(self.cpu),
                "storage": f"{self.disk}GB",
                "config": config_str,
                "os_version": os_version,
                "status": "running",
                "suspended": False,
                "whitelisted": False,
                "suspended_reason": "",
                "suspension_history": [],
                "created_at": datetime.now().isoformat(),
                "shared_with": [],
                "id": None
            }
            vps_data[user_id].append(vps_info)
            save_vps_data()
            
            if self.ctx.guild:
                vps_role = await get_or_create_vps_role(self.ctx.guild)
                if vps_role:
                    try:
                        await self.user.add_roles(vps_role, reason=f"{BOT_NAME} VPS ownership granted")
                    except discord.Forbidden:
                        logger.warning(f"Failed to assign {BOT_NAME} VPS role to {self.user.name}")
            
            success_embed = discord.Embed(
                title="✅ VPS Created Successfully",
                color=0x00ff88
            )
            add_field(success_embed, "Owner", self.user.mention, True)
            add_field(success_embed, "VPS ID", f"#{vps_count}", True)
            add_field(success_embed, "Container", f"`{container_name}`", True)
            add_field(success_embed, "Resources", f"**RAM:** {self.ram}GB\n**CPU:** {self.cpu} Cores\n**Storage:** {self.disk}GB", False)
            add_field(success_embed, "OS", os_version, True)
            
            await interaction.followup.send(embed=success_embed)
            
            try:
                dm_embed = discord.Embed(
                    title=f"✅ {BOT_NAME} - VPS Created!",
                    description=f"Your VPS has been successfully deployed by an admin!",
                    color=0x00ff88
                )
                
                created_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                vps_details = f"**VPS ID:** #{vps_count}\n"
                vps_details += f"**Container Name:** `{container_name}`\n"
                vps_details += f"**Configuration:** {config_str}\n"
                vps_details += f"**Status:** Running\n"
                vps_details += f"**OS:** {os_version}\n"
                vps_details += f"**Created:** {created_time}"
                
                dm_embed.add_field(name="⌯⌲ VPS Details", value=vps_details, inline=False)
                dm_embed.add_field(name="⌯⌲ Management", 
                                 value=f"• Use `{PREFIX}manage` to start/stop/reinstall your VPS\n• Use `{PREFIX}manage` → SSH for terminal access\n• Contact admin for upgrades or issues", 
                                 inline=False)
                dm_embed.add_field(name="⌯⌲ Important Notes", 
                                 value="• Full root access via SSH\n• Docker-ready with nesting and privileged mode\n• Back up your data regularly", 
                                 inline=False)
                if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                    dm_embed.set_thumbnail(url=THUMBNAIL)
                if BANNER and BANNER.startswith(('http://', 'https://')):
                    dm_embed.set_image(url=BANNER)
                dm_embed.set_footer(text=f"Powered by {BOT_NAME} • Premium VPS Management • {datetime.now().strftime('%d-%m-%Y %H:%M')}")
                
                await self.user.send(embed=dm_embed)
            except discord.Forbidden:
                await self.ctx.send(embed=create_info_embed("Notification Failed", f"Couldn't send DM to {self.user.mention}. Please ensure DMs are enabled."))
            except Exception as e:
                logger.error(f"Failed to send DM to {self.user.id}: {e}")
        
        except Exception as e:
            error_embed = create_error_embed("Creation Failed", f"Error: {str(e)}")
            await interaction.followup.send(embed=error_embed)

@bot.command(name='delete-vps')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def delete_vps(ctx, user: discord.Member, vps_number: int, *, reason: str = "No reason"):
    """Delete user's VPS"""
    user_id = str(user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or user doesn't have a VPS."))
        return
    
    vps = vps_data[user_id][vps_number - 1]
    container_name = vps["container_name"]
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM port_forwards WHERE vps_container = ?', (container_name,))
    conn.commit()
    conn.close()
    
    await ctx.send(embed=create_info_embed("Deleting VPS", f"Removing VPS #{vps_number}..."))
    
    try:
        await execute_lxc(f"lxc delete {container_name} --force")
        
        del vps_data[user_id][vps_number - 1]
        if not vps_data[user_id]:
            del vps_data[user_id]
            if ctx.guild:
                vps_role = await get_or_create_vps_role(ctx.guild)
                if vps_role and vps_role in user.roles:
                    try:
                        await user.remove_roles(vps_role, reason="No VPS ownership")
                    except discord.Forbidden:
                        logger.warning(f"Failed to remove VPS role from {user.name}")
        
        save_vps_data()
        
        embed = discord.Embed(
            title="✅ VPS Deleted Successfully",
            color=0x00ff88
        )
        embed.add_field(name="⌯⌲ Owner", value=user.mention, inline=True)
        embed.add_field(name="⌯⌲ VPS ID", value=f"#{vps_number}", inline=True)
        embed.add_field(name="⌯⌲ Container", value=f"`{container_name}`", inline=True)
        embed.add_field(name="⌯⌲ Reason", value=reason, inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        
        await ctx.send(embed=embed)
    
    except Exception as e:
        await ctx.send(embed=create_error_embed("Deletion Failed", f"Error: {str(e)}"))

@bot.command(name='add-resources')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def add_resources(ctx, container_name: str, ram: int = None, cpu: int = None, disk: int = None):
    """Add resources to VPS"""
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to add"))
        return
    
    found_vps = None
    user_id = None
    vps_index = None
    
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No VPS found with ID: `{container_name}`"))
        return
    
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping VPS `{container_name}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {container_name}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    
    changes = []
    try:
        current_ram_gb = int(found_vps['ram'].replace('GB', ''))
        current_cpu = int(found_vps['cpu'])
        current_disk_gb = int(found_vps['storage'].replace('GB', ''))
        
        new_ram_gb = current_ram_gb
        new_cpu = current_cpu
        new_disk_gb = current_disk_gb
        
        if ram is not None and ram > 0:
            new_ram_gb += ram
            ram_mb = new_ram_gb * 1024
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            changes.append(f"RAM: +{ram}GB (New total: {new_ram_gb}GB)")
        
        if cpu is not None and cpu > 0:
            new_cpu += cpu
            await execute_lxc(f"lxc config set {container_name} limits.cpu {new_cpu}")
            changes.append(f"CPU: +{cpu} cores (New total: {new_cpu} cores)")
        
        if disk is not None and disk > 0:
            new_disk_gb += disk
            await execute_lxc(f"lxc config device set {container_name} root size={new_disk_gb}GB")
            changes.append(f"Disk: +{disk}GB (New total: {new_disk_gb}GB)")
        
        found_vps['ram'] = f"{new_ram_gb}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk_gb}GB"
        found_vps['config'] = f"{new_ram_gb}GB RAM / {new_cpu} CPU / {new_disk_gb}GB Disk"
        vps_data[user_id][vps_index] = found_vps
        save_vps_data()
        
        if was_running:
            await execute_lxc(f"lxc start {container_name}")
            found_vps['status'] = 'running'
            save_vps_data()
            await apply_internal_permissions(container_name)
        
        embed = discord.Embed(
            title="✅ Resources Added",
            description=f"Successfully added resources to VPS `{container_name}`",
            color=0x00ff88
        )
        embed.add_field(name="⌯⌲ Changes Applied", value="\n".join(changes), inline=False)
        if disk_changed:
            embed.add_field(name="⌯⌲ Disk Note", value="Run `sudo resize2fs /` inside the VPS to expand the filesystem.", inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        
        await ctx.send(embed=embed)
    
    except Exception as e:
        await ctx.send(embed=create_error_embed("Resource Addition Failed", f"Error: {str(e)}"))

@bot.command(name='resize-vps')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def resize_vps(ctx, container_name: str, ram: int = None, cpu: int = None, disk: int = None):
    """Resize VPS resources"""
    await add_resources(ctx, container_name, ram, cpu, disk)

@bot.command(name='suspend-vps')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def suspend_vps(ctx, container_name: str, *, reason: str = "Admin action"):
    """Suspend VPS"""
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if vps.get('status') != 'running':
                    await ctx.send(embed=create_error_embed("Cannot Suspend", "VPS must be running to suspend."))
                    return
                try:
                    await execute_lxc(f"lxc stop {container_name}")
                    vps['status'] = 'stopped'
                    vps['suspended'] = True
                    vps['suspended_reason'] = reason
                    if 'suspension_history' not in vps:
                        vps['suspension_history'] = []
                    vps['suspension_history'].append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': f"{ctx.author.name}"
                    })
                    save_vps_data()
                    log_suspension(container_name, uid, 'suspend', reason, str(ctx.author.id))
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Suspend Failed", str(e)))
                    return
                
                embed = discord.Embed(
                    title="⏸ VPS Suspended",
                    description=f"VPS `{container_name}` suspended.",
                    color=0xffaa00
                )
                embed.add_field(name="⌯⌲ Reason", value=reason, inline=False)
                if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                    embed.set_thumbnail(url=THUMBNAIL)
                if BANNER and BANNER.startswith(('http://', 'https://')):
                    embed.set_image(url=BANNER)
                embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
                await ctx.send(embed=embed)
                found = True
                break
        if found:
            break
    
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"VPS `{container_name}` not found."))

@bot.command(name='unsuspend-vps')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def unsuspend_vps(ctx, container_name: str):
    """Unsuspend VPS"""
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if not vps.get('suspended', False):
                    await ctx.send(embed=create_error_embed("Not Suspended", "VPS is not suspended."))
                    return
                try:
                    vps['suspended'] = False
                    vps['suspended_reason'] = ''
                    vps['status'] = 'running'
                    await execute_lxc(f"lxc start {container_name}")
                    await apply_internal_permissions(container_name)
                    save_vps_data()
                    log_suspension(container_name, uid, 'unsuspend', '', str(ctx.author.id))
                    
                    embed = discord.Embed(
                        title="▶ VPS Unsuspended",
                        description=f"VPS `{container_name}` unsuspended and started.",
                        color=0x00ff88
                    )
                    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                        embed.set_thumbnail(url=THUMBNAIL)
                    if BANNER and BANNER.startswith(('http://', 'https://')):
                        embed.set_image(url=BANNER)
                    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
                    await ctx.send(embed=embed)
                    found = True
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Start Failed", str(e)))
                break
        if found:
            break
    
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"VPS `{container_name}` not found."))

@bot.command(name='suspension-logs')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def suspension_logs(ctx, container_name: str = None):
    """View suspension logs"""
    logs = get_suspension_logs(container_name)
    
    if not logs:
        await ctx.send(embed=create_info_embed("Suspension Logs", "No logs found."))
        return
    
    log_text = ""
    for log in logs[:10]:
        log_text += f"**{log['action']}** - {log['container_name']}\n"
        log_text += f"Time: {log['created_at'][:19]}\n"
        if log['reason']:
            log_text += f"Reason: {log['reason']}\n"
        log_text += "\n"
    
    embed = discord.Embed(
        title="📋 Suspension Logs",
        description=log_text,
        color=0x00ccff
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='whitelist-vps')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def whitelist_vps(ctx, container_name: str, action: str):
    """Whitelist VPS from auto-suspend"""
    action = action.lower()
    if action not in ['add', 'remove']:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use `add` or `remove`."))
        return
    
    found = False
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                if action == 'add':
                    vps['whitelisted'] = True
                    msg = "added to whitelist (exempt from auto-suspension)"
                else:
                    vps['whitelisted'] = False
                    msg = "removed from whitelist"
                save_vps_data()
                
                embed = discord.Embed(
                    title="✅ Whitelist Updated",
                    description=f"VPS `{container_name}` {msg}.",
                    color=0x00ff88
                )
                if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                    embed.set_thumbnail(url=THUMBNAIL)
                if BANNER and BANNER.startswith(('http://', 'https://')):
                    embed.set_image(url=BANNER)
                embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
                await ctx.send(embed=embed)
                found = True
                break
        if found:
            break
    
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"VPS `{container_name}` not found."))

@bot.command(name='userinfo')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def user_info(ctx, user: discord.Member):
    """User information"""
    user_id = str(user.id)
    vps_list = vps_data.get(user_id, [])
    
    embed = discord.Embed(
        title=f"User Information - {user.name}",
        description=f"Detailed information for {user.mention}",
        color=0x1a1a1a
    )
    
    user_details = f"**Name:** {user.name}\n"
    user_details += f"**ID:** {user.id}\n"
    user_details += f"**Joined:** {user.joined_at.strftime('%Y-%m-%d %H:%M:%S') if user.joined_at else 'Unknown'}"
    
    embed.add_field(name="⌯⌲ User Details", value=user_details, inline=False)
    
    if vps_list:
        vps_info = []
        for i, vps in enumerate(vps_list):
            status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
            vps_info.append(f"{status_emoji} VPS {i+1}: `{vps['container_name']}` - {vps.get('status', 'unknown').upper()}")
        
        embed.add_field(name="⌯⌲ VPS List", value="\n".join(vps_info), inline=False)
    else:
        embed.add_field(name="⌯⌲ VPS Information", value="**No VPS owned**", inline=False)
    
    port_quota = get_user_allocation(user_id)
    port_used = get_user_used_ports(user_id)
    embed.add_field(name="⌯⌲ Port Quota", value=f"Allocated: {port_quota}, Used: {port_used}", inline=False)
    
    is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    embed.add_field(name="⌯⌲ Admin Status", value=f"**{'Yes' if is_admin_user else 'No'}**", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    
    await ctx.send(embed=embed)

@bot.command(name='list-all')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def list_all_vps(ctx):
    """List all VPS"""
    total_vps = sum(len(v) for v in vps_data.values())
    total_users = len(vps_data)
    
    embed = discord.Embed(
        title="All VPS Information",
        description=f"**Total Users:** {total_users}\n**Total VPS:** {total_vps}",
        color=0x1a1a1a
    )
    
    vps_info = []
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            for i, vps in enumerate(vps_list):
                status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
                status_text = vps.get('status', 'unknown').upper()
                if vps.get('suspended', False):
                    status_text += " (SUSPENDED)"
                if vps.get('whitelisted', False):
                    status_text += " (WHITELISTED)"
                vps_info.append(f"{status_emoji} **{user.name}** - VPS {i+1}: `{vps['container_name']}` - {status_text}")
        except:
            vps_info.append(f"❓ Unknown User ({user_id}) - {len(vps_list)} VPS")
    
    if vps_info:
        vps_text = "\n".join(vps_info[:15])
        embed.add_field(name="⌯⌲ VPS List", value=vps_text, inline=False)
        if len(vps_info) > 15:
            embed.add_field(name="⌯⌲ Note", value=f"Showing 15 of {len(vps_info)} VPS", inline=False)
    
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='exec')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def execute_command(ctx, container_name: str, *, command: str):
    """Execute command in VPS"""
    await ctx.send(embed=create_info_embed("Executing Command", f"Running command in VPS `{container_name}`..."))
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode() if stdout else "No output"
        error = stderr.decode() if stderr else ""
        
        embed = discord.Embed(
            title=f"Command Output - {container_name}",
            description=f"Command: `{command}`",
            color=0x1a1a1a
        )
        
        if output.strip():
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            embed.add_field(name="⌯⌲ Output", value=f"```\n{output}\n```", inline=False)
        
        if error.strip():
            if len(error) > 1000:
                error = error[:1000] + "\n... (truncated)"
            embed.add_field(name="⌯⌲ Error", value=f"```\n{error}\n```", inline=False)
        
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    
    except Exception as e:
        await ctx.send(embed=create_error_embed("Execution Failed", f"Error: {str(e)}"))

@bot.command(name='stop-vps-all')
@is_admin()
@commands.cooldown(1, 30, commands.BucketType.user)
async def stop_all_vps(ctx):
    """Stop all VPS"""
    embed = discord.Embed(
        title="⚠️ Stopping All VPS",
        description="This will stop ALL running VPS on the server.\n\nThis action cannot be undone. Continue?",
        color=0xffaa00
    )
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="Stop All VPS", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            try:
                await execute_lxc("lxc stop --all --force")
                
                stopped_count = 0
                for user_id, vps_list in vps_data.items():
                    for vps in vps_list:
                        if vps.get('status') == 'running':
                            vps['status'] = 'stopped'
                            stopped_count += 1
                
                save_vps_data()
                embed = discord.Embed(
                    title="✅ All VPS Stopped",
                    description=f"Successfully stopped {stopped_count} VPS",
                    color=0x00ff88
                )
                if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                    embed.set_thumbnail(url=THUMBNAIL)
                if BANNER and BANNER.startswith(('http://', 'https://')):
                    embed.set_image(url=BANNER)
                embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
                await interaction.followup.send(embed=embed)
            except Exception as e:
                embed = create_error_embed("Stop Failed", str(e))
                await interaction.followup.send(embed=embed)
        
        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            embed = discord.Embed(
                title="Operation Cancelled",
                description="The stop all VPS operation has been cancelled.",
                color=0x00ccff
            )
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await interaction.response.edit_message(embed=embed, view=None)
    
    await ctx.send(embed=embed, view=ConfirmView())

@bot.command(name='migrate-vps')
@is_admin()
@commands.cooldown(1, 30, commands.BucketType.user)
async def migrate_vps(ctx, container_name: str, pool: str):
    """Migrate VPS to another storage pool"""
    await ctx.send(embed=create_info_embed("Migrating VPS", f"Migrating `{container_name}` to pool `{pool}`..."))
    
    try:
        await execute_lxc(f"lxc move {container_name} -s {pool}")
        embed = discord.Embed(
            title="✅ VPS Migrated",
            description=f"VPS `{container_name}` migrated to pool `{pool}`",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Migration Failed", f"Error: {str(e)}"))

@bot.command(name='vps-network')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def vps_network(ctx, container_name: str, action: str, value: str = None):
    """Network management for VPS"""
    actions = ['list', 'limit', 'add', 'remove']
    
    if action not in actions:
        await ctx.send(embed=create_error_embed("Invalid Action", f"Use: {', '.join(actions)}"))
        return
    
    try:
        if action == 'list':
            proc = await asyncio.create_subprocess_exec(
                "lxc", "exec", container_name, "--", "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                output = stdout.decode()
                if len(output) > 1900:
                    output = output[:1900] + "..."
                embed = discord.Embed(
                    title=f"Network - {container_name}",
                    description=f"```\n{output}\n```",
                    color=0x00ccff
                )
            else:
                embed = create_error_embed("Error", f"Failed to list network interfaces")
        elif action == 'limit' and value:
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.egress {value}")
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.ingress {value}")
            embed = discord.Embed(
                title="✅ Network Limit Set",
                description=f"Set network limit to {value} for `{container_name}`",
                color=0x00ff88
            )
        else:
            embed = create_error_embed("Invalid Command", "Usage: .vps-network <container> <list|limit> [value]")
        
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Network Operation Failed", str(e)))

@bot.command(name='apply-permissions')
@is_admin()
@commands.cooldown(1, 10, commands.BucketType.user)
async def apply_permissions(ctx, container_name: str):
    """Apply Docker-ready permissions to VPS"""
    await ctx.send(embed=create_info_embed("Applying Permissions", f"Applying Docker-ready permissions to `{container_name}`..."))
    
    try:
        await apply_lxc_config(container_name)
        await apply_internal_permissions(container_name)
        embed = discord.Embed(
            title="✅ Permissions Applied",
            description=f"Docker-ready permissions applied to `{container_name}`",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Failed", f"Error: {str(e)}"))

# ============ SYSTEM COMMANDS ============

@bot.command(name='thresholds')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def thresholds(ctx):
    """Show current resource thresholds"""
    embed = discord.Embed(
        title="📊 Resource Thresholds",
        description=f"**CPU:** {CPU_THRESHOLD}%\n**RAM:** {RAM_THRESHOLD}%",
        color=0x00ccff
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='set-threshold')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def set_threshold(ctx, cpu: int, ram: int):
    """Set resource thresholds"""
    global CPU_THRESHOLD, RAM_THRESHOLD
    
    if cpu < 0 or ram < 0:
        await ctx.send(embed=create_error_embed("Invalid Thresholds", "Thresholds must be non-negative."))
        return
    
    CPU_THRESHOLD = cpu
    RAM_THRESHOLD = ram
    set_setting('cpu_threshold', str(cpu))
    set_setting('ram_threshold', str(ram))
    
    embed = discord.Embed(
        title="✅ Thresholds Updated",
        description=f"**CPU:** {cpu}%\n**RAM:** {ram}%",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='serverstats')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def server_stats(ctx):
    """Server statistics"""
    total_containers = sum(len(v) for v in vps_data.values())
    running_containers = 0
    suspended_containers = 0
    
    for vps_list in vps_data.values():
        for vps in vps_list:
            if vps.get('status') == 'running':
                running_containers += 1
            if vps.get('suspended', False):
                suspended_containers += 1
    
    latency = round(bot.latency * 1000)
    
    embed = discord.Embed(
        title="📊 Server Statistics",
        color=0x00ccff
    )
    
    host_info = f"**Bot Latency:** {latency}ms\n"
    host_info += f"**Prefix:** `{PREFIX}`"
    
    vps_info = f"**Total VPS:** {total_containers}\n"
    vps_info += f"**Running:** {running_containers}\n"
    vps_info += f"**Suspended:** {suspended_containers}\n"
    vps_info += f"**Total Users:** {len(vps_data)}"
    
    embed.add_field(name="⌯⌲ Host Information", value=host_info, inline=True)
    embed.add_field(name="⌯⌲ VPS Overview", value=vps_info, inline=True)
    
    uptime = get_uptime()
    embed.add_field(name="⌯⌲ System Uptime", value=uptime, inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    
    await ctx.send(embed=embed)

@bot.command(name='lxc-list')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def lxc_list(ctx):
    """List all LXC containers"""
    try:
        result = await execute_lxc("lxc list")
        embed = discord.Embed(
            title="📋 LXC Containers List",
            description=f"```\n{result}\n```",
            color=0x00ccff
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Error", str(e)))

@bot.command(name='set-status')
@is_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def set_status(ctx, activity_type: str, *, name: str):
    """Set bot status"""
    types = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
    }
    
    if activity_type.lower() not in types:
        await ctx.send(embed=create_error_embed("Invalid Type", "Valid types: playing, watching, listening"))
        return
    
    await bot.change_presence(activity=discord.Activity(type=types[activity_type.lower()], name=name))
    set_setting('bot_activity', activity_type.lower())
    set_setting('bot_activity_name', name)
    
    embed = discord.Embed(
        title="✅ Status Updated",
        description=f"Set to {activity_type}: {name}",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='change-mode')
@is_main_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def change_mode(ctx, mode: str):
    """Change bot mode"""
    modes = {
        'online': discord.Status.online,
        'idle': discord.Status.idle,
        'dnd': discord.Status.dnd,
    }
    
    if mode.lower() not in modes:
        await ctx.send(embed=create_error_embed("Invalid Mode", "Valid modes: online, idle, dnd"))
        return
    
    await bot.change_presence(status=modes[mode.lower()])
    set_setting('bot_status', mode.lower())
    
    embed = discord.Embed(
        title="✅ Mode Changed",
        description=f"Bot mode set to {mode}",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='maintenance')
@is_main_admin()
@commands.cooldown(1, 5, commands.BucketType.user)
async def maintenance_mode(ctx, mode: str):
    """Toggle maintenance mode"""
    global MAINTENANCE_MODE, MAINTENANCE_STARTED_BY, MAINTENANCE_STARTED_AT
    
    mode = mode.lower()
    if mode not in ['on', 'off']:
        await ctx.send(embed=create_error_embed("Invalid Mode", "Please use `on` or `off`."))
        return
    
    if mode == 'on':
        MAINTENANCE_MODE = True
        MAINTENANCE_STARTED_BY = str(ctx.author.id)
        MAINTENANCE_STARTED_AT = datetime.now().isoformat()
        
        set_setting('maintenance_mode', 'true')
        set_setting('maintenance_started_by', str(ctx.author.id))
        set_setting('maintenance_started_at', MAINTENANCE_STARTED_AT)
        
        await bot.change_presence(status=discord.Status.idle, activity=discord.Game(name="🔧 Maintenance Mode"))
        
        embed = discord.Embed(
            title="🔧 Maintenance Mode Active",
            description="The bot is now in maintenance mode. Only administrators can use commands.",
            color=0xffaa00
        )
        embed.add_field(name="⌯⌲ Started By", value=ctx.author.mention, inline=True)
        embed.add_field(name="⌯⌲ Status", value="Commands disabled for non-admins", inline=True)
        
    else:
        MAINTENANCE_MODE = False
        MAINTENANCE_STARTED_BY = ''
        MAINTENANCE_STARTED_AT = ''
        
        set_setting('maintenance_mode', 'false')
        set_setting('maintenance_started_by', '')
        set_setting('maintenance_started_at', '')
        
        activity_types = {
            'playing': discord.ActivityType.playing,
            'watching': discord.ActivityType.watching,
            'listening': discord.ActivityType.listening,
        }
        activity_type = activity_types.get(BOT_ACTIVITY, discord.ActivityType.watching)
        status_types = {
            'online': discord.Status.online,
            'idle': discord.Status.idle,
            'dnd': discord.Status.dnd,
        }
        status = status_types.get(BOT_STATUS, discord.Status.online)
        
        await bot.change_presence(status=status, activity=discord.Activity(type=activity_type, name=BOT_ACTIVITY_NAME))
        
        embed = discord.Embed(
            title="✅ Maintenance Mode Deactivated",
            description="All commands are now available.",
            color=0x00ff88
        )
    
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='purge-data')
@is_main_admin()
@commands.cooldown(1, 60, commands.BucketType.user)
async def purge_data(ctx, user: discord.Member):
    """Purge all data for a user"""
    user_id = str(user.id)
    
    if user_id not in vps_data:
        await ctx.send(embed=create_error_embed("No Data", f"{user.mention} has no VPS data."))
        return
    
    embed = discord.Embed(
        title="⚠️ Purge Data",
        description=f"This will permanently delete ALL VPS data for {user.mention}.\n"
                    f"This action CANNOT be undone!\n\n"
                    f"**VPS Count:** {len(vps_data[user_id])}\n\n"
                    f"Type `{PREFIX}confirm-purge {user.id}` to proceed.",
        color=0xffaa00
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

@bot.command(name='confirm-purge')
@is_main_admin()
@commands.cooldown(1, 60, commands.BucketType.user)
async def confirm_purge(ctx, user_id: str):
    """Confirm purge of user data"""
    try:
        user = await bot.fetch_user(int(user_id))
    except:
        user = None
    
    if user_id not in vps_data:
        await ctx.send(embed=create_error_embed("No Data", f"User ID {user_id} has no VPS data."))
        return
    
    deleted_count = 0
    for vps in vps_data[user_id][:]:
        try:
            await execute_lxc(f"lxc delete {vps['container_name']} --force")
            deleted_count += 1
        except:
            pass
    
    del vps_data[user_id]
    save_vps_data()
    
    embed = discord.Embed(
        title="✅ Data Purged",
        description=f"Successfully purged data for {user.mention if user else f'User {user_id}'}\n"
                    f"Deleted {deleted_count} VPS containers.",
        color=0x00ff88
    )
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)

# ============ PORT FORWARDING COMMANDS ============

@bot.command(name='ports')
@commands.cooldown(1, 2, commands.BucketType.user)
async def ports_command(ctx, subcmd: str = None, *args):
    """Manage port forwarding"""
    if not await maintenance_check(ctx):
        return
    
    user_id = str(ctx.author.id)
    allocated = get_user_allocation(user_id)
    used = get_user_used_ports(user_id)
    available = allocated - used
    
    if subcmd is None:
        embed = discord.Embed(
            title="🔌 Port Forwarding Help",
            description=f"**Your Quota:** Allocated: {allocated}, Used: {used}, Available: {available}",
            color=0x00ccff
        )
        embed.add_field(name="⌯⌲ Commands", 
                       value=f"{PREFIX}ports add <vps_num> <vps_port>\n{PREFIX}ports list\n{PREFIX}ports remove <id>", 
                       inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
        return
    
    if subcmd == 'add':
        if len(args) < 2:
            await ctx.send(embed=create_error_embed("Usage", f"Usage: {PREFIX}ports add <vps_number> <vps_port>"))
            return
        
        try:
            vps_num = int(args[0])
            vps_port = int(args[1])
            if vps_port < 1 or vps_port > 65535:
                raise ValueError
        except ValueError:
            await ctx.send(embed=create_error_embed("Invalid Input", "VPS number and port must be positive integers (port: 1-65535)."))
            return
        
        vps_list = vps_data.get(user_id, [])
        if vps_num < 1 or vps_num > len(vps_list):
            await ctx.send(embed=create_error_embed("Invalid VPS", f"Invalid VPS number (1-{len(vps_list)}). Use {PREFIX}myvps to list."))
            return
        
        vps = vps_list[vps_num - 1]
        container = vps['container_name']
        
        if used >= allocated:
            await ctx.send(embed=create_error_embed("Quota Exceeded", f"No available slots. Allocated: {allocated}, Used: {used}. Contact admin for more."))
            return
        
        host_port = await create_port_forward(user_id, container, vps_port)
        if host_port:
            embed = discord.Embed(
                title="✅ Port Forward Created",
                description=f"VPS #{vps_num} port {vps_port} (TCP/UDP) forwarded to host port {host_port}.",
                color=0x00ff88
            )
            embed.add_field(name="⌯⌲ Access", value=f"External: {YOUR_SERVER_IP}:{host_port} → VPS:{vps_port} (TCP & UDP)", inline=False)
            embed.add_field(name="⌯⌲ Quota Update", value=f"Used: {used + 1}/{allocated}", inline=False)
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Failed", "Could not assign host port. Try again later."))
    
    elif subcmd == 'list':
        forwards = get_user_forwards(user_id)
        embed = discord.Embed(
            title="Your Port Forwards",
            description=f"**Quota:** Allocated: {allocated}, Used: {used}, Available: {available}",
            color=0x00ccff
        )
        
        if not forwards:
            embed.add_field(name="⌯⌲ Forwards", value="No active port forwards.", inline=False)
        else:
            text = []
            for f in forwards:
                vps_num = next((i+1 for i, v in enumerate(vps_data.get(user_id, [])) if v['container_name'] == f['vps_container']), 'Unknown')
                created = datetime.fromisoformat(f['created_at']).strftime('%Y-%m-%d %H:%M')
                text.append(f"**ID {f['id']}** - VPS #{vps_num}: {f['vps_port']} (TCP/UDP) → {f['host_port']} (Created: {created})")
            
            embed.add_field(name="⌯⌲ Active Forwards", value="\n".join(text[:10]), inline=False)
            if len(forwards) > 10:
                embed.add_field(name="⌯⌲ Note", value=f"Showing 10 of {len(forwards)}. Remove unused with {PREFIX}ports remove <id>.", inline=False)
        
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    
    elif subcmd == 'remove':
        if len(args) < 1:
            await ctx.send(embed=create_error_embed("Usage", f"Usage: {PREFIX}ports remove <forward_id>"))
            return
        
        try:
            fid = int(args[0])
        except ValueError:
            await ctx.send(embed=create_error_embed("Invalid ID", "Forward ID must be an integer."))
            return
        
        success, _ = await remove_port_forward(fid)
        if success:
            embed = discord.Embed(
                title="✅ Removed",
                description=f"Port forward {fid} removed (TCP & UDP).",
                color=0x00ff88
            )
            embed.add_field(name="⌯⌲ Quota Update", value=f"Used: {used - 1}/{allocated}", inline=False)
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                embed.set_image(url=BANNER)
            embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Not Found", "Forward ID not found. Use .ports list."))
    
    else:
        await ctx.send(embed=create_error_embed("Invalid Subcommand", f"Use: add <vps_num> <port>, list, remove <id>"))

@bot.command(name='ports-add-user')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def ports_add_user(ctx, amount: int, user: discord.Member):
    """Allocate port slots to a user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be a positive integer."))
        return
    
    user_id = str(user.id)
    allocate_ports(user_id, amount)
    
    embed = discord.Embed(
        title="✅ Ports Allocated",
        description=f"Allocated {amount} port slots to {user.mention}.",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Quota", value=f"Total: {get_user_allocation(user_id)} slots", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)
    
    try:
        dm_embed = discord.Embed(
            title="Port Slots Allocated",
            description=f"You have been granted {amount} additional port forwarding slots by an admin.\nUse `{PREFIX}ports list` to view your quota and active forwards.",
            color=0x00ccff
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            dm_embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            dm_embed.set_image(url=BANNER)
        dm_embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await user.send(embed=dm_embed)
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("DM Failed", f"Could not notify {user.mention} via DM."))

@bot.command(name='ports-remove-user')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def ports_remove_user(ctx, amount: int, user: discord.Member):
    """Deallocate port slots from a user"""
    if amount <= 0:
        await ctx.send(embed=create_error_embed("Invalid Amount", "Amount must be a positive integer."))
        return
    
    user_id = str(user.id)
    current = get_user_allocation(user_id)
    if amount > current:
        amount = current
    
    deallocate_ports(user_id, amount)
    remaining = get_user_allocation(user_id)
    
    embed = discord.Embed(
        title="✅ Ports Deallocated",
        description=f"Removed {amount} port slots from {user.mention}.",
        color=0x00ff88
    )
    embed.add_field(name="⌯⌲ Remaining Quota", value=f"{remaining} slots", inline=False)
    if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
        embed.set_thumbnail(url=THUMBNAIL)
    if BANNER and BANNER.startswith(('http://', 'https://')):
        embed.set_image(url=BANNER)
    embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
    await ctx.send(embed=embed)
    
    try:
        dm_embed = discord.Embed(
            title="Port Slots Reduced",
            description=f"Your port forwarding quota has been reduced by {amount} slots by an admin.\nRemaining: {remaining} slots.",
            color=0xffaa00
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            dm_embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            dm_embed.set_image(url=BANNER)
        dm_embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await user.send(embed=dm_embed)
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("DM Failed", f"Could not notify {user.mention} via DM."))

@bot.command(name='ports-revoke')
@is_admin()
@commands.cooldown(1, 3, commands.BucketType.user)
async def ports_revoke(ctx, forward_id: int):
    """Revoke a port forward"""
    success, user_id = await remove_port_forward(forward_id, is_admin=True)
    if success and user_id:
        try:
            user = await bot.fetch_user(int(user_id))
            dm_embed = discord.Embed(
                title="Port Forward Revoked",
                description=f"One of your port forwards (ID: {forward_id}) has been revoked by an admin.",
                color=0xffaa00
            )
            if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
                dm_embed.set_thumbnail(url=THUMBNAIL)
            if BANNER and BANNER.startswith(('http://', 'https://')):
                dm_embed.set_image(url=BANNER)
            dm_embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
            await user.send(embed=dm_embed)
        except:
            pass
        embed = discord.Embed(
            title="✅ Revoked",
            description=f"Port forward ID {forward_id} revoked.",
            color=0x00ff88
        )
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        await ctx.send(embed=embed)
    else:
        await ctx.send(embed=create_error_embed("Failed", "Port forward ID not found or removal failed."))

# ============ HELP SYSTEM ============

class HelpView(discord.ui.View):
    def __init__(self, ctx):
        super().__init__(timeout=300)
        self.ctx = ctx
        self.current_category = "user"
        self.message = None
        
        self.select = discord.ui.Select(
            placeholder="Select a category...",
            options=[
                discord.SelectOption(label="👤 User Commands", value="user", description="Basic commands for all users"),
                discord.SelectOption(label="🖥️ VPS Management", value="vps", description="Manage your VPS containers"),
                discord.SelectOption(label="🔌 Port Forwarding", value="ports", description="Manage port forwards"),
                discord.SelectOption(label="🤖 Bot System Commands", value="bot_system", description="Bot economy and stats"),
                discord.SelectOption(label="⚙️ System Commands", value="system", description="Bot and system commands"),
                discord.SelectOption(label="🛡️ Admin Commands", value="admin", description="Administrator commands"),
                discord.SelectOption(label="👑 Main Admin Commands", value="main_admin", description="Main administrator commands"),
            ]
        )
        self.select.callback = self.select_callback
        self.add_item(self.select)
        
        self.update_embed()
    
    async def select_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.ctx.author.id:
            await interaction.response.send_message("This help menu is not for you!", ephemeral=True)
            return
        
        self.current_category = interaction.data["values"][0]
        self.update_embed()
        await interaction.response.edit_message(embed=self.embed, view=self)
    
    def update_embed(self):
        colors = {
            "user": 0x3498db,
            "vps": 0x2ecc71,
            "ports": 0xe74c3c,
            "bot_system": 0x9b59b6,
            "system": 0xf39c12,
            "admin": 0xe67e22,
            "main_admin": 0xf1c40f
        }
        
        color = colors.get(self.current_category, 0x5865F2)
        
        if self.current_category == "user":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 👤 User Commands",
                description="Basic commands available to all users",
                color=color
            )
            commands = [
                f"**`{PREFIX}ping`** - Check bot latency",
                f"**`{PREFIX}uptime`** - Show host uptime",
                f"**`{PREFIX}plans`** - View free VPS plans",
                f"**`{PREFIX}freeplans`** - Free plans list",
                f"**`{PREFIX}myvps`** - List your VPS",
                f"**`{PREFIX}list`** - Detailed VPS list",
                f"**`{PREFIX}manage`** - Manage your VPS",
                f"**`{PREFIX}manage @user`** - Manage another user's VPS (Admin only)",
                f"**`{PREFIX}share-user @user <vps_number>`** - Share VPS access",
                f"**`{PREFIX}share-ruser @user <vps_number>`** - Revoke VPS access",
                f"**`{PREFIX}manage-shared @owner <vps_number>`** - Manage shared VPS"
            ]
            total = 11
            
        elif self.current_category == "vps":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 🖥️ VPS Management",
                description="Commands for managing your VPS",
                color=color
            )
            commands = [
                f"**`{PREFIX}myvps`** - List your VPS",
                f"**`{PREFIX}list`** - Detailed VPS list",
                f"**`{PREFIX}vpsinfo [container]`** - VPS information",
                f"**`{PREFIX}vps-stats <container>`** - VPS stats",
                f"**`{PREFIX}restart-vps <container>`** - Restart VPS (Admin)",
                f"**`{PREFIX}clone-vps <container> [new_name]`** - Clone VPS (Admin)",
                f"**`{PREFIX}snapshot <container> [snap_name]`** - Create snapshot (Admin)",
                f"**`{PREFIX}restore-backup <container> <snap_name>`** - Restore VPS (Admin)"
            ]
            total = 8
            
        elif self.current_category == "ports":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 🔌 Port Forwarding",
                description="Manage port forwarding for your VPS",
                color=color
            )
            commands = [
                f"**`{PREFIX}ports`** - Port forwarding help",
                f"**`{PREFIX}ports add <vps_num> <port>`** - Add port forward",
                f"**`{PREFIX}ports list`** - List your port forwards",
                f"**`{PREFIX}ports remove <id>`** - Remove port forward",
                f"**`{PREFIX}ports-add-user <amount> @user`** - Allocate ports (Admin)",
                f"**`{PREFIX}ports-remove-user <amount> @user`** - Deallocate ports (Admin)",
                f"**`{PREFIX}ports-revoke <id>`** - Revoke port forward (Admin)"
            ]
            total = 7
            
        elif self.current_category == "bot_system":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 🤖 Bot System Commands",
                description="Bot economy and statistics commands",
                color=color
            )
            commands = [
                f"**`{PREFIX}plans`** - View free VPS plans",
                f"**`{PREFIX}addinv @user <amount>`** - Add invites (Admin)",
                f"**`{PREFIX}removeinv @user <amount>`** - Remove invites (Admin)",
                f"**`{PREFIX}addboost @user <amount>`** - Add boosts (Admin)",
                f"**`{PREFIX}removeboost @user <amount>`** - Remove boosts (Admin)",
                f"**`{PREFIX}credits @user <amount>`** - Add credits (Admin)",
                f"**`{PREFIX}dailycredit`** - Claim daily credits",
                f"**`{PREFIX}edit-plans`** - Edit VPS plans (Main Admin)"
            ]
            total = 8
            
        elif self.current_category == "system":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - ⚙️ System Commands",
                description="Bot and system management commands",
                color=color
            )
            commands = [
                f"**`{PREFIX}ping`** - Check bot latency",
                f"**`{PREFIX}uptime`** - Show host uptime",
                f"**`{PREFIX}serverstats`** - Server statistics (Admin)",
                f"**`{PREFIX}thresholds`** - View resource thresholds",
                f"**`{PREFIX}set-threshold <cpu> <ram>`** - Set thresholds (Admin)",
                f"**`{PREFIX}set-status <type> <name>`** - Set bot status (Admin)",
                f"**`{PREFIX}change-mode <mode>`** - Change bot mode (Main Admin)",
                f"**`{PREFIX}maintenance <on/off>`** - Maintenance mode (Main Admin)",
                f"**`{PREFIX}lxc-list`** - List all LXC containers (Admin)"
            ]
            total = 9
            
        elif self.current_category == "admin":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 🛡️ Admin Commands",
                description="Commands for server administrators",
                color=color
            )
            commands = [
                f"**`{PREFIX}create <ram> <cpu> <disk> @user`** - Create VPS",
                f"**`{PREFIX}delete-vps @user <vps_number> [reason]`** - Delete VPS",
                f"**`{PREFIX}add-resources <container> [ram] [cpu] [disk]`** - Add resources",
                f"**`{PREFIX}resize-vps <container> [ram] [cpu] [disk]`** - Resize VPS",
                f"**`{PREFIX}suspend-vps <container> [reason]`** - Suspend VPS",
                f"**`{PREFIX}unsuspend-vps <container>`** - Unsuspend VPS",
                f"**`{PREFIX}suspension-logs [container]`** - View suspension logs",
                f"**`{PREFIX}whitelist-vps <container> <add|remove>`** - Whitelist VPS",
                f"**`{PREFIX}userinfo @user`** - User information",
                f"**`{PREFIX}list-all`** - List all VPS",
                f"**`{PREFIX}exec <container> <command>`** - Execute command",
                f"**`{PREFIX}stop-vps-all`** - Stop all VPS",
                f"**`{PREFIX}restart-vps <container>`** - Restart VPS",
                f"**`{PREFIX}clone-vps <container> [new_name]`** - Clone VPS",
                f"**`{PREFIX}snapshot <container> [snap_name]`** - Create snapshot",
                f"**`{PREFIX}restore-backup <container> <snap_name>`** - Restore backup",
                f"**`{PREFIX}vpsinfo [container]`** - VPS information",
                f"**`{PREFIX}vps-stats <container>`** - VPS stats"
            ]
            total = 18
            
        elif self.current_category == "main_admin":
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help - 👑 Main Admin Commands",
                description="Commands for the main administrator",
                color=color
            )
            commands = [
                f"**`{PREFIX}admin-add @user`** - Add admin",
                f"**`{PREFIX}admin-remove @user`** - Remove admin",
                f"**`{PREFIX}admin-list`** - List admins",
                f"**`{PREFIX}maintenance <on/off>`** - Maintenance mode",
                f"**`{PREFIX}set-status <type> <name>`** - Set bot status",
                f"**`{PREFIX}change-mode <mode>`** - Change bot mode",
                f"**`{PREFIX}edit-plans`** - Edit VPS plans",
                f"**`{PREFIX}purge-data @user`** - Purge user data",
                f"**`{PREFIX}confirm-purge <user_id>`** - Confirm purge"
            ]
            total = 9
            
        else:
            embed = discord.Embed(
                title=f"📚 {BOT_NAME} Help",
                description="Select a category from the dropdown",
                color=color
            )
            commands = []
            total = 0
        
        embed.add_field(name="⌯⌲ Commands", value="\n".join(commands) if commands else "No commands available", inline=False)
        embed.add_field(name="⌯⌲ Navigation", 
                       value=f"• Use dropdown to switch categories\n• Total commands: {total}\n• Prefix: `{PREFIX}`", 
                       inline=False)
        if THUMBNAIL and THUMBNAIL.startswith(('http://', 'https://')):
            embed.set_thumbnail(url=THUMBNAIL)
        if BANNER and BANNER.startswith(('http://', 'https://')):
            embed.set_image(url=BANNER)
        embed.set_footer(text=f"{BOT_NAME} • Cloud Services")
        
        self.embed = embed

@bot.command(name='help')
@commands.cooldown(1, 3, commands.BucketType.user)
async def help_command(ctx):
    """Show interactive help menu"""
    if not await maintenance_check(ctx):
        return
    
    # Check if user already has an active help menu
    user_id = ctx.author.id
    if user_id in active_help_menus:
        try:
            await active_help_menus[user_id].delete()
        except:
            pass
        del active_help_menus[user_id]
    
    view = HelpView(ctx)
    msg = await ctx.send(embed=view.embed, view=view)
    active_help_menus[user_id] = msg
    
    # Remove from dict when menu expires
    async def remove_from_dict():
        await asyncio.sleep(300)
        if user_id in active_help_menus:
            del active_help_menus[user_id]
    
    asyncio.create_task(remove_from_dict())

@bot.command(name='commands')
@commands.cooldown(1, 3, commands.BucketType.user)
async def commands_alias(ctx):
    """Alias for help command"""
    await help_command(ctx)

# ============ TYPO HANDLING ============

@bot.command(name='mangage')
async def manage_typo(ctx):
    """Handle typo for manage command"""
    embed = create_info_embed("Command Correction", f"Did you mean `{PREFIX}manage`? Use the correct command.")
    await ctx.send(embed=embed)

# ============ RUN THE BOT ============

if __name__ == "__main__":
    if DISCORD_TOKEN:
        bot.run(DISCORD_TOKEN)
    else:
        logger.error("No Discord token found in DISCORD_TOKEN environment variable.")
