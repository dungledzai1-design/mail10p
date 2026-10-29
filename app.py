import os
import time
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, session, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'letiendung-pokemon-secret-key-2026-xyz999')
CORS(app)

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'database.db'))
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'dungledzvl')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    # Table keys
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS license_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_string TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        max_devices INTEGER DEFAULT 1,
        note TEXT DEFAULT '',
        bound_device_id TEXT DEFAULT NULL,
        bound_client_type TEXT DEFAULT NULL,
        total_playtime_sec INTEGER DEFAULT 0
    )
    ''')

    # Table sessions / online tracking 24/7
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_string TEXT NOT NULL,
        device_id TEXT NOT NULL,
        client_type TEXT DEFAULT 'Unknown',
        game_account TEXT DEFAULT 'Khách',
        ip_address TEXT DEFAULT '',
        last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_online INTEGER DEFAULT 1
    )
    ''')

    # Table system configuration & remote toggles
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_config (
        key_name TEXT PRIMARY KEY,
        value_data TEXT
    )
    ''')

    # Insert default configs if not exists
    default_configs = {
        'maintenance_mode': '0',
        'maintenance_msg': 'Hệ thống đang bảo trì để cập nhật tính năng mới!',
        'announcement': 'Chào mừng bạn đến với Letiendung Mod Pokemon v2.6!',
        'feature_god_mode': '1',
        'feature_one_hit': '1',
        'feature_unlock_all': '1',
        'feature_full_shiny': '1',
        'feature_currency': '1',
        'feature_auto_farm': '1',
        'feature_auto_levelup': '1',
        'feature_auto_collect': '1',
        'feature_overnight': '1',
        'feature_auto_gacha': '1',
        'feature_vietnamese': '1',
        'min_version': '2.6.0'
    }

    for k, v in default_configs.items():
        cursor.execute('INSERT OR IGNORE INTO system_config (key_name, value_data) VALUES (?, ?)', (k, v))

    cursor.execute('''
    INSERT OR IGNORE INTO license_keys (key_string, expires_at, is_active, max_devices, note)
    VALUES (?, ?, 1, 1, ?)
    ''', ('VIP-LETD-2026-TEST', None, 'Key VIP Trải Nghiệm'))

    conn.commit()
    conn.close()

init_db()

def get_config(key_name, default=''):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT value_data FROM system_config WHERE key_name = ?', (key_name,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else default

def set_config(key_name, value_data):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO system_config (key_name, value_data) VALUES (?, ?)', (key_name, str(value_data)))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            if request.path.startswith('/api/admin/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập quản trị'}), 401
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Generate crypto signature for response payload
def sign_payload(data):
    s = json.dumps(data, sort_keys=True) + ADMIN_PASSWORD + 'pokemon_salt_2026'
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

# ----------------- CLIENT EXTENSION APIS -----------------

@app.route('/api/verify-key', methods=['POST'])
def verify_key():
    data = request.get_json(silent=True) or {}
    key_str = (data.get('key') or '').strip()
    device_id = (data.get('device_id') or '').strip()
    client_type = data.get('client_type') or 'PC'
    game_account = (data.get('game_account') or 'Khách').strip()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not key_str:
        return jsonify({'success': False, 'message': 'Vui lòng nhập License Key!'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM license_keys WHERE key_string = ?', (key_str,))
    k = c.fetchone()

    if not k:
        conn.close()
        return jsonify({'success': False, 'message': 'Key không tồn tại hoặc đã bị xóa!'}), 404

    if not k['is_active']:
        conn.close()
        return jsonify({'success': False, 'message': 'Key này đã bị quản trị viên khóa/tạm dừng!'}), 403

    # Check expiration
    if k['expires_at']:
        try:
            exp_time = datetime.strptime(k['expires_at'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > exp_time:
                conn.close()
                return jsonify({'success': False, 'message': f'Key đã hết hạn sử dụng vào lúc {k["expires_at"]}! Vui lòng liên hệ Admin gia hạn.'}), 403
        except Exception:
            pass

    # Check device binding
    bound_dev = k['bound_device_id']
    if not bound_dev and device_id:
        # First time binding
        c.execute('UPDATE license_keys SET bound_device_id = ?, bound_client_type = ? WHERE key_string = ?',
                  (device_id, client_type, key_str))
        conn.commit()
    elif bound_dev and bound_dev != device_id:
        conn.close()
        return jsonify({
            'success': False,
            'message': 'Key đã được liên kết với thiết bị khác! Liên hệ Admin để reset thiết bị.'
        }), 403

    # Update or insert session
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('SELECT id FROM user_sessions WHERE key_string = ? AND device_id = ?', (key_str, device_id))
    existing_sess = c.fetchone()
    if existing_sess:
        c.execute('''
        UPDATE user_sessions
        SET client_type = ?, game_account = ?, ip_address = ?, last_heartbeat = ?, is_online = 1
        WHERE id = ?
        ''', (client_type, game_account, ip, now_str, existing_sess['id']))
    else:
        c.execute('''
        INSERT INTO user_sessions (key_string, device_id, client_type, game_account, ip_address, last_heartbeat, session_start, is_online)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (key_str, device_id, client_type, game_account, ip, now_str, now_str))

    conn.commit()
    conn.close()

    # Remote features & config
    m_mode = get_config('maintenance_mode', '0') == '1'
    m_msg = get_config('maintenance_msg', '')
    announcement = get_config('announcement', '')
    features = {
        'godMode': get_config('feature_god_mode', '1') == '1',
        'oneHit': get_config('feature_one_hit', '1') == '1',
        'unlockAll': get_config('feature_unlock_all', '1') == '1',
        'fullShiny': get_config('feature_full_shiny', '1') == '1',
        'setCurrency': get_config('feature_currency', '1') == '1',
        'autoFarm': get_config('feature_auto_farm', '1') == '1',
        'autoPlay': get_config('feature_auto_farm', '1') == '1',
        'autoLevelUp': get_config('feature_auto_levelup', '1') == '1',
        'autoCollect': get_config('feature_auto_collect', '1') == '1',
        'overnight': get_config('feature_overnight', '1') == '1',
        'autoGacha': get_config('feature_auto_gacha', '1') == '1',
        'vietnamese': get_config('feature_vietnamese', '1') == '1',
    }

    resp_payload = {
        'success': True,
        'message': 'Xác thực Key thành công! Chúc bạn chơi game vui vẻ.',
        'key': key_str,
        'expires_at': k['expires_at'] or 'Vĩnh viễn',
        'note': k['note'],
        'server_time': now_str,
        'maintenance': m_mode,
        'maintenance_msg': m_msg,
        'announcement': announcement,
        'features': features
    }
    resp_payload['token'] = sign_payload(resp_payload)
    return jsonify(resp_payload)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json(silent=True) or {}
    key_str = (data.get('key') or '').strip()
    device_id = (data.get('device_id') or '').strip()
    game_account = (data.get('game_account') or 'Khách').strip()
    delta_seconds = int(data.get('delta_sec') or 30)
    if delta_seconds > 120 or delta_seconds < 0:
        delta_seconds = 30
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not key_str or not device_id:
        return jsonify({'valid': False, 'message': 'Thiếu thông tin xác thực'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM license_keys WHERE key_string = ?', (key_str,))
    k = c.fetchone()

    if not k or not k['is_active']:
        conn.close()
        return jsonify({'valid': False, 'message': 'Key không còn hiệu lực hoặc đã bị thu hồi!'})

    # Check expiration
    if k['expires_at']:
        try:
            exp_time = datetime.strptime(k['expires_at'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > exp_time:
                conn.close()
                return jsonify({'valid': False, 'message': 'Key đã hết hạn!'})
        except Exception:
            pass

    # Update total playtime
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('UPDATE license_keys SET total_playtime_sec = total_playtime_sec + ? WHERE key_string = ?', (delta_seconds, key_str))

    # Update session
    c.execute('''
    UPDATE user_sessions
    SET game_account = ?, ip_address = ?, last_heartbeat = ?, is_online = 1
    WHERE key_string = ? AND device_id = ?
    ''', (game_account, ip, now_str, key_str, device_id))

    conn.commit()
    conn.close()

    m_mode = get_config('maintenance_mode', '0') == '1'
    m_msg = get_config('maintenance_msg', '')
    features = {
        'godMode': get_config('feature_god_mode', '1') == '1',
        'oneHit': get_config('feature_one_hit', '1') == '1',
        'unlockAll': get_config('feature_unlock_all', '1') == '1',
        'fullShiny': get_config('feature_full_shiny', '1') == '1',
        'setCurrency': get_config('feature_currency', '1') == '1',
        'autoFarm': get_config('feature_auto_farm', '1') == '1',
        'autoPlay': get_config('feature_auto_farm', '1') == '1',
        'autoLevelUp': get_config('feature_auto_levelup', '1') == '1',
        'autoCollect': get_config('feature_auto_collect', '1') == '1',
        'overnight': get_config('feature_overnight', '1') == '1',
        'autoGacha': get_config('feature_auto_gacha', '1') == '1',
        'vietnamese': get_config('feature_vietnamese', '1') == '1',
    }

    return jsonify({
        'valid': True,
        'maintenance': m_mode,
        'maintenance_msg': m_msg,
        'features': features,
        'server_time': now_str
    })

# ----------------- ADMIN DASHBOARD & APIS -----------------

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect('/')

    error = None
    if request.method == 'POST':
        pwd = request.form.get('password', '').strip()
        if pwd == ADMIN_PASSWORD:
            session['is_admin'] = True
            session.permanent = True
            return redirect('/')
        else:
            error = 'Mật khẩu quản trị không đúng!'

    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect('/login')

@app.route('/')
@login_required
def dashboard_view():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def admin_stats():
    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM license_keys')
    total_keys = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM license_keys WHERE is_active = 1')
    active_keys = c.fetchone()[0]

    # Threshold for online: heartbeat within last 75 seconds
    cutoff = (datetime.now() - timedelta(seconds=75)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('SELECT COUNT(DISTINCT device_id) FROM user_sessions WHERE last_heartbeat >= ?', (cutoff,))
    online_users = c.fetchone()[0]

    c.execute('SELECT SUM(total_playtime_sec) FROM license_keys')
    total_sec = c.fetchone()[0] or 0
    total_hours = round(total_sec / 3600, 1)

    c.execute('SELECT COUNT(DISTINCT game_account) FROM user_sessions WHERE game_account != "Khách"')
    total_game_accounts = c.fetchone()[0]

    conn.close()

    return jsonify({
        'success': True,
        'total_keys': total_keys,
        'active_keys': active_keys,
        'online_users': online_users,
        'total_hours': total_hours,
        'total_game_accounts': total_game_accounts
    })

@app.route('/api/admin/keys', methods=['GET'])
@login_required
def admin_get_keys():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
    SELECT k.*,
           (SELECT game_account FROM user_sessions WHERE user_sessions.key_string = k.key_string ORDER BY last_heartbeat DESC LIMIT 1) as last_game_acc,
           (SELECT last_heartbeat FROM user_sessions WHERE user_sessions.key_string = k.key_string ORDER BY last_heartbeat DESC LIMIT 1) as last_seen,
           (SELECT ip_address FROM user_sessions WHERE user_sessions.key_string = k.key_string ORDER BY last_heartbeat DESC LIMIT 1) as last_ip
    FROM license_keys k
    ORDER BY k.id DESC
    ''')
    rows = c.fetchall()
    conn.close()

    cutoff = datetime.now() - timedelta(seconds=75)
    keys_list = []
    for r in rows:
        d = dict(r)
        # Check expired
        is_expired = False
        if d['expires_at']:
            try:
                exp_dt = datetime.strptime(d['expires_at'], '%Y-%m-%d %H:%M:%S')
                is_expired = datetime.now() > exp_dt
            except Exception:
                pass
        d['is_expired'] = is_expired

        # Check online
        is_online = False
        if d['last_seen']:
            try:
                seen_dt = datetime.strptime(d['last_seen'], '%Y-%m-%d %H:%M:%S')
                is_online = seen_dt >= cutoff
            except Exception:
                pass
        d['is_online'] = is_online
        d['playtime_formatted'] = f"{d['total_playtime_sec'] // 3600}h {(d['total_playtime_sec'] % 3600) // 60}m"
        keys_list.append(d)

    return jsonify({'success': True, 'keys': keys_list})

@app.route('/api/admin/keys/create', methods=['POST'])
@login_required
def admin_create_key():
    data = request.get_json(silent=True) or {}
    duration_type = data.get('duration_type', '30d') # 1d, 7d, 30d, 90d, 365d, lifetime, custom
    custom_hours = int(data.get('custom_hours') or 24)
    note = (data.get('note') or '').strip()
    quantity = min(50, max(1, int(data.get('quantity') or 1)))
    custom_key = (data.get('custom_key') or '').strip().upper()

    now = datetime.now()
    if duration_type == '1d':
        exp = now + timedelta(days=1)
    elif duration_type == '7d':
        exp = now + timedelta(days=7)
    elif duration_type == '30d':
        exp = now + timedelta(days=30)
    elif duration_type == '90d':
        exp = now + timedelta(days=90)
    elif duration_type == '365d':
        exp = now + timedelta(days=365)
    elif duration_type == 'custom':
        exp = now + timedelta(hours=custom_hours)
    else:
        exp = None # lifetime

    exp_str = exp.strftime('%Y-%m-%d %H:%M:%S') if exp else None

    conn = get_db()
    c = conn.cursor()
    created = []

    for i in range(quantity):
        if quantity == 1 and custom_key:
            key_code = custom_key
        else:
            token = secrets.token_hex(4).upper()
            token2 = secrets.token_hex(4).upper()
            key_code = f"PKM-{token}-{token2}"

        try:
            c.execute('''
            INSERT INTO license_keys (key_string, expires_at, is_active, max_devices, note)
            VALUES (?, ?, 1, 1, ?)
            ''', (key_code, exp_str, note))
            created.append(key_code)
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'count': len(created), 'keys': created})

@app.route('/api/admin/keys/extend', methods=['POST'])
@login_required
def admin_extend_key():
    data = request.get_json(silent=True) or {}
    key_str = data.get('key')
    add_days = int(data.get('days') or 30)

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT expires_at FROM license_keys WHERE key_string = ?', (key_str,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Key không tồn tại'}), 404

    current_exp = row['expires_at']
    if current_exp:
        try:
            curr_dt = datetime.strptime(current_exp, '%Y-%m-%d %H:%M:%S')
            base_dt = max(datetime.now(), curr_dt)
        except Exception:
            base_dt = datetime.now()
    else:
        base_dt = datetime.now()

    new_exp = (base_dt + timedelta(days=add_days)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('UPDATE license_keys SET expires_at = ?, is_active = 1 WHERE key_string = ?', (new_exp, key_str))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'new_expires_at': new_exp})

@app.route('/api/admin/keys/toggle', methods=['POST'])
@login_required
def admin_toggle_key():
    data = request.get_json(silent=True) or {}
    key_str = data.get('key')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT is_active FROM license_keys WHERE key_string = ?', (key_str,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Key không tồn tại'}), 404

    new_state = 0 if row['is_active'] else 1
    c.execute('UPDATE license_keys SET is_active = ? WHERE key_string = ?', (new_state, key_str))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'is_active': new_state})

@app.route('/api/admin/keys/delete', methods=['POST'])
@login_required
def admin_delete_key():
    data = request.get_json(silent=True) or {}
    key_str = data.get('key')
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM license_keys WHERE key_string = ?', (key_str,))
    c.execute('DELETE FROM user_sessions WHERE key_string = ?', (key_str,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/keys/reset-hwid', methods=['POST'])
@login_required
def admin_reset_hwid():
    data = request.get_json(silent=True) or {}
    key_str = data.get('key')
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE license_keys SET bound_device_id = NULL, bound_client_type = NULL WHERE key_string = ?', (key_str,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Đã gỡ liên kết thiết bị thành công! Người dùng có thể kích hoạt máy mới.'})

@app.route('/api/admin/online', methods=['GET'])
@login_required
def admin_get_online():
    conn = get_db()
    c = conn.cursor()
    cutoff = (datetime.now() - timedelta(seconds=75)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''
    SELECT s.*, k.note, k.expires_at, k.total_playtime_sec
    FROM user_sessions s
    JOIN license_keys k ON s.key_string = k.key_string
    WHERE s.last_heartbeat >= ?
    ORDER BY s.last_heartbeat DESC
    ''', (cutoff,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'online_list': rows})

@app.route('/api/admin/config', methods=['GET', 'POST'])
@login_required
def admin_config():
    if request.method == 'GET':
        return jsonify({
            'maintenance_mode': get_config('maintenance_mode', '0') == '1',
            'maintenance_msg': get_config('maintenance_msg', ''),
            'announcement': get_config('announcement', ''),
            'feature_god_mode': get_config('feature_god_mode', '1') == '1',
            'feature_one_hit': get_config('feature_one_hit', '1') == '1',
            'feature_unlock_all': get_config('feature_unlock_all', '1') == '1',
            'feature_full_shiny': get_config('feature_full_shiny', '1') == '1',
            'feature_currency': get_config('feature_currency', '1') == '1',
            'feature_auto_farm': get_config('feature_auto_farm', '1') == '1',
            'feature_auto_levelup': get_config('feature_auto_levelup', '1') == '1',
            'feature_auto_collect': get_config('feature_auto_collect', '1') == '1',
            'feature_overnight': get_config('feature_overnight', '1') == '1',
            'feature_auto_gacha': get_config('feature_auto_gacha', '1') == '1',
            'feature_vietnamese': get_config('feature_vietnamese', '1') == '1',
        })
    else:
        data = request.get_json(silent=True) or {}
        if 'maintenance_mode' in data:
            set_config('maintenance_mode', '1' if data['maintenance_mode'] else '0')
        if 'maintenance_msg' in data:
            set_config('maintenance_msg', data['maintenance_msg'])
        if 'announcement' in data:
            set_config('announcement', data['announcement'])
        for fkey in ['feature_god_mode', 'feature_one_hit', 'feature_unlock_all', 'feature_full_shiny', 'feature_currency', 'feature_auto_farm', 'feature_auto_levelup', 'feature_auto_collect', 'feature_overnight', 'feature_auto_gacha', 'feature_vietnamese']:
            if fkey in data:
                set_config(fkey, '1' if data[fkey] else '0')
        return jsonify({'success': True, 'message': 'Đã cập nhật cài đặt hệ thống!'})


# ----------------- HTML TEMPLATES -----------------

LOGIN_HTML = '''<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Server Key — Đăng Nhập</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body {
      background: radial-gradient(circle at center, #131722 0%, #0a0c10 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      padding: 20px;
    }
    .card {
      background: rgba(22, 27, 34, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(16px);
      width: 100%;
      max-width: 420px;
      padding: 36px 30px;
      border-radius: 20px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 35px rgba(239, 68, 68, 0.15);
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, #ef4444, #f59e0b, #10b981, #6366f1);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 20px;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    h2 { font-size: 24px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; }
    p.sub { font-size: 14px; color: #8b949e; margin-bottom: 28px; }
    .input-group { margin-bottom: 22px; text-align: left; }
    label { display: block; font-size: 13px; color: #c9d1d9; margin-bottom: 8px; font-weight: 500; }
    input[type="password"] {
      width: 100%;
      padding: 13px 16px;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 12px;
      color: #fff;
      font-size: 15px;
      outline: none;
      transition: all 0.2s;
    }
    input[type="password"]:focus {
      border-color: #ef4444;
      box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
    }
    button {
      width: 100%;
      padding: 13px;
      background: linear-gradient(135deg, #ef4444, #dc2626);
      border: none;
      border-radius: 12px;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);
    }
    button:hover { opacity: 0.95; transform: translateY(-1px); }
    .error {
      background: rgba(239, 68, 68, 0.15);
      color: #fca5a5;
      padding: 10px;
      border-radius: 10px;
      font-size: 13px;
      margin-bottom: 18px;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .footer { margin-top: 24px; font-size: 12px; color: #6e7681; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">⚡ SERVER KEY ADMIN</div>
    <h2>Letiendung Mod Pokemon</h2>
    <p class="sub">Hệ thống quản lý bản quyền & điều khiển từ xa</p>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    <form method="POST">
      <div class="input-group">
        <label>Mật khẩu Quản Trị Viên</label>
        <input type="password" name="password" placeholder="Nhập mật khẩu..." autofocus required>
      </div>
      <button type="submit">Đăng Nhập Quản Trị</button>
    </form>
    <div class="footer">Dành riêng cho Admin Dũng Lê • PokeSurvivor Mod 2026</div>
  </div>
</body>
</html>
'''

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard — Letiendung Mod Pokemon</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111726;
      --card-border: #1e293b;
      --primary: #ef4444;
      --primary-hover: #dc2626;
      --accent: #38bdf8;
      --success: #10b981;
      --warning: #f59e0b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
    }
    * { margin:0; padding:0; box-sizing:border-box; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; padding-bottom: 50px; }
    .container { max-width: 1280px; margin: 0 auto; padding: 24px; }

    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 28px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-logo {
      width: 44px; height: 44px;
      background: linear-gradient(135deg, #ef4444, #f59e0b);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px; color: #fff;
      box-shadow: 0 0 20px rgba(239, 68, 68, 0.4);
    }
    .brand-title h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
    .brand-title p { font-size: 13px; color: var(--text-muted); }
    .header-actions { display: flex; align-items: center; gap: 12px; }
    .btn {
      padding: 9px 16px;
      border-radius: 10px;
      font-size: 13.5px;
      font-weight: 600;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      transition: all 0.2s;
    }
    .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-hover)); color: #fff; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.35); }
    .btn-primary:hover { opacity: 0.92; transform: translateY(-1px); }
    .btn-secondary { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
    .btn-secondary:hover { background: #334155; color: #fff; }
    .btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.35); }
    .btn-success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 18px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    .stat-info h3 { font-size: 13px; color: var(--text-muted); font-weight: 500; margin-bottom: 6px; }
    .stat-info .num { font-size: 26px; font-weight: 700; color: #fff; }
    .stat-icon {
      width: 48px; height: 48px;
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 20px;
    }
    .stat-icon.red { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .stat-icon.green { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .stat-icon.blue { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
    .stat-icon.yellow { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }

    /* Control Panel Box */
    .panel-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 22px;
      margin-bottom: 28px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    .panel-box-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--card-border);
    }
    .panel-box-header h2 { font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .toggle-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }
    .toggle-item {
      background: #0d121f;
      border: 1px solid #1e293b;
      padding: 14px 16px;
      border-radius: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .toggle-label { font-size: 13.5px; font-weight: 500; }
    .toggle-switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
    }
    .toggle-switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; inset: 0;
      background-color: #334155;
      transition: .3s;
      border-radius: 24px;
    }
    .slider:before {
      position: absolute; content: "";
      height: 18px; width: 18px; left: 3px; bottom: 3px;
      background-color: white;
      transition: .3s;
      border-radius: 50%;
    }
    input:checked + .slider { background-color: var(--primary); }
    input:checked + .slider:before { transform: translateX(20px); }

    .msg-row { display: flex; gap: 12px; margin-top: 14px; }
    .msg-row input {
      flex: 1;
      padding: 10px 14px;
      background: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 10px;
      color: #fff;
      font-size: 13.5px;
      outline: none;
    }
    .msg-row input:focus { border-color: var(--accent); }

    /* Tables & Nav Tabs */
    .tabs { display: flex; gap: 10px; margin-bottom: 18px; border-bottom: 1px solid var(--card-border); padding-bottom: 10px; }
    .tab-btn {
      padding: 8px 16px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-radius: 8px;
      display: flex; align-items: center; gap: 7px;
    }
    .tab-btn.active { background: #1e293b; color: #fff; }
    .tab-badge { background: var(--primary); color: #fff; font-size: 11px; padding: 2px 7px; border-radius: 10px; }

    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      overflow-x: auto;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13.5px; }
    th {
      background: #0d121f;
      padding: 14px 18px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
      text-transform: uppercase;
      font-size: 11.5px;
      letter-spacing: 0.5px;
    }
    td { padding: 14px 18px; border-bottom: 1px solid #192231; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    .key-badge {
      font-family: monospace;
      font-weight: 700;
      background: #1e293b;
      padding: 4px 8px;
      border-radius: 6px;
      color: #38bdf8;
      border: 1px solid #334155;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .status-active { background: rgba(16, 185, 129, 0.15); color: #34d399; }
    .status-expired { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .status-locked { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .online-indicator {
      width: 9px; height: 9px; border-radius: 50%;
      background: #10b981;
      display: inline-block;
      box-shadow: 0 0 10px #10b981;
    }

    /* Modal */
    .modal {
      display: none;
      position: fixed; inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(6px);
      z-index: 999;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .modal.show { display: flex; }
    .modal-content {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      width: 100%;
      max-width: 480px;
      padding: 26px;
      box-shadow: 0 25px 50px -12px rgba(0,0,0,0.8);
    }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .modal-header h3 { font-size: 18px; font-weight: 700; }
    .modal-close { background: none; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 6px; font-weight: 500; }
    .form-group input, .form-group select {
      width: 100%;
      padding: 10px 14px;
      background: #0d121f;
      border: 1px solid var(--card-border);
      border-radius: 10px;
      color: #fff;
      font-size: 14px;
      outline: none;
    }
    .form-group input:focus, .form-group select:focus { border-color: var(--primary); }
    .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }

    /* Toast */
    #toast {
      position: fixed; bottom: 25px; right: 25px;
      background: #1e293b; color: #fff;
      padding: 12px 20px; border-radius: 10px;
      border-left: 4px solid var(--primary);
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      font-size: 13.5px; z-index: 10000;
      opacity: 0; transform: translateY(20px);
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
    }
    #toast.show { opacity: 1; transform: translateY(0); }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="brand">
        <div class="brand-logo"><i class="fa-solid fa-gamepad"></i></div>
        <div class="brand-title">
          <h1>Admin Server Key — Letiendung Mod</h1>
          <p>Quản lý bản quyền, thời gian người chơi & điều khiển từ xa</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary" onclick="refreshData()"><i class="fa-solid fa-rotate"></i> Làm mới</button>
        <button class="btn btn-primary" onclick="openCreateModal()"><i class="fa-solid fa-plus"></i> Tạo Key Mới</button>
        <a href="/logout" class="btn btn-danger"><i class="fa-solid fa-right-from-bracket"></i> Đăng xuất</a>
      </div>
    </header>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-info">
          <h3>TỔNG KEY</h3>
          <div class="num" id="stat-total-keys">0</div>
        </div>
        <div class="stat-icon red"><i class="fa-solid fa-key"></i></div>
      </div>
      <div class="stat-card">
        <div class="stat-info">
          <h3>ĐANG ONLINE (24/7)</h3>
          <div class="num" id="stat-online-users">0</div>
        </div>
        <div class="stat-icon green"><i class="fa-solid fa-tower-broadcast"></i></div>
      </div>
      <div class="stat-card">
        <div class="stat-info">
          <h3>TỔNG GIỜ CÀY TOOL</h3>
          <div class="num" id="stat-total-hours">0h</div>
        </div>
        <div class="stat-icon blue"><i class="fa-solid fa-clock"></i></div>
      </div>
      <div class="stat-card">
        <div class="stat-info">
          <h3>ACC POKEMON KẾT NỐI</h3>
          <div class="num" id="stat-total-accounts">0</div>
        </div>
        <div class="stat-icon yellow"><i class="fa-solid fa-users"></i></div>
      </div>
    </div>

    <!-- Remote Control & Maintenance Panel -->
    <div class="panel-box">
      <div class="panel-box-header">
        <h2><i class="fa-solid fa-sliders"></i> Điều Khiển Chức Năng Từ Xa (Remote Control) & Bảo Trì</h2>
        <span style="font-size:12px; color:var(--text-muted);">Admin tắt bật chức năng sẽ tác động ngay lập tức tới tất cả tool người dùng</span>
      </div>
      <div class="toggle-grid" style="grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));">
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-shield-halved" style="color:#ef4444; margin-right:6px;"></i> God Mode (Bất tử)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-god" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-bolt" style="color:#f59e0b; margin-right:6px;"></i> One-Hit (Giết ngay)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-onehit" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-unlock-keyhole" style="color:#38bdf8; margin-right:6px;"></i> Mở khoá All Pokemon</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-unlock" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-star" style="color:#fbbf24; margin-right:6px;"></i> Full Shiny 966 Pokemon</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-fullshiny" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-coins" style="color:#eab308; margin-right:6px;"></i> Chỉnh Vàng & Vé Gacha</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-currency" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-robot" style="color:#10b981; margin-right:6px;"></i> Tự Động Di Chuyển</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-autofarm" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-wand-magic-sparkles" style="color:#a855f7; margin-right:6px;"></i> Tự Chọn Thẻ Nâng Cấp</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-autolevel" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-magnet" style="color:#06b6d4; margin-right:6px;"></i> Tự Nhặt Đồ / Xu / Rương</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-autocollect" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-moon" style="color:#818cf8; margin-right:6px;"></i> Treo Máy Qua Đêm</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-overnight" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-dice" style="color:#ec4899; margin-right:6px;"></i> Tự Quay Gacha</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-autogacha" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-language" style="color:#22c55e; margin-right:6px;"></i> Dịch Tiếng Việt</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-vietnamese" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div class="toggle-item">
          <span class="toggle-label"><i class="fa-solid fa-triangle-exclamation" style="color:#ef4444; margin-right:6px;"></i> Chế Độ Bảo Trì Khẩn Cấp</span>
          <label class="toggle-switch">
            <input type="checkbox" id="cfg-maintenance" onchange="updateRemoteConfig()">
            <span class="slider"></span>
          </label>
        </div>
      </div>
      <div class="msg-row">
        <input type="text" id="cfg-maintenance-msg" placeholder="Thông báo bảo trì hiển thị trên tool..." value="">
        <input type="text" id="cfg-announcement" placeholder="Thông báo nổi bật (Banner)..." value="">
        <button class="btn btn-secondary" onclick="updateRemoteConfig()"><i class="fa-solid fa-floppy-disk"></i> Lưu Cấu Hình</button>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs">
      <button class="tab-btn active" id="tab-btn-keys" onclick="switchTab('keys')">
        <i class="fa-solid fa-key"></i> Quản Lý Danh Sách Key
      </button>
      <button class="tab-btn" id="tab-btn-online" onclick="switchTab('online')">
        <i class="fa-solid fa-wifi"></i> Đang Chơi Realtime 24/7 <span class="tab-badge" id="online-count-badge">0</span>
      </button>
    </div>

    <!-- View: Keys List -->
    <div id="view-keys">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>License Key</th>
              <th>Khách Hàng / Ghi Chú</th>
              <th>Trạng Thái</th>
              <th>Thiết Bị (PC / Kiwi)</th>
              <th>Tài Khoản Game</th>
              <th>Thời Gian Cày</th>
              <th>Hạn Sử Dụng</th>
              <th>Thao Tác</th>
            </tr>
          </thead>
          <tbody id="keys-table-body">
            <tr><td colspan="8" style="text-align:center; padding:30px;">Đang tải danh sách...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- View: Realtime Online List -->
    <div id="view-online" style="display:none;">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Trạng Thái</th>
              <th>Tài Khoản Game (PokeSurvivor)</th>
              <th>License Key</th>
              <th>Thiết Bị (Nền tảng)</th>
              <th>IP Người Dùng</th>
              <th>Tổng Giờ Cày</th>
              <th>Ping Gần Nhất</th>
            </tr>
          </thead>
          <tbody id="online-table-body">
            <tr><td colspan="7" style="text-align:center; padding:30px;">Chưa có người dùng nào đang online</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Modal Tạo Key Mới -->
  <div class="modal" id="create-modal">
    <div class="modal-content">
      <div class="modal-header">
        <h3>Tạo License Key Mới</h3>
        <button class="modal-close" onclick="closeCreateModal()">&times;</button>
      </div>
      <div class="form-group">
        <label>Thời hạn sử dụng</label>
        <select id="modal-duration">
          <option value="1d">1 Ngày (24 giờ)</option>
          <option value="7d">7 Ngày (1 tuần)</option>
          <option value="30d" selected>30 Ngày (1 tháng)</option>
          <option value="90d">90 Ngày (3 tháng)</option>
          <option value="365d">1 Năm</option>
          <option value="lifetime">Vĩnh Viễn</option>
        </select>
      </div>
      <div class="form-group">
        <label>Ghi chú / Tên khách mua</label>
        <input type="text" id="modal-note" placeholder="VD: Anh Nam, Khách Facebook...">
      </div>
      <div class="form-group">
        <label>Tuỳ chọn: Đặt mã Key theo ý muốn (Để trống sẽ tự sinh mã đẹp)</label>
        <input type="text" id="modal-custom-key" placeholder="VD: VIP-NAM-2026">
      </div>
      <div class="form-group">
        <label>Số lượng tạo (Tối đa 50 key)</label>
        <input type="number" id="modal-quantity" value="1" min="1" max="50">
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeCreateModal()">Hủy</button>
        <button class="btn btn-primary" onclick="submitCreateKey()"><i class="fa-solid fa-check"></i> Xác Nhận Tạo</button>
      </div>
    </div>
  </div>

  <!-- Toast notification -->
  <div id="toast"></div>

  <script>
    let currentTab = 'keys';

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2800);
    }

    function switchTab(tab) {
      currentTab = tab;
      document.getElementById('view-keys').style.display = tab === 'keys' ? 'block' : 'none';
      document.getElementById('view-online').style.display = tab === 'online' ? 'block' : 'none';
      document.getElementById('tab-btn-keys').classList.toggle('active', tab === 'keys');
      document.getElementById('tab-btn-online').classList.toggle('active', tab === 'online');
      refreshData();
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();
        if (data.success) {
          document.getElementById('stat-total-keys').textContent = data.total_keys;
          document.getElementById('stat-online-users').textContent = data.online_users;
          document.getElementById('online-count-badge').textContent = data.online_users;
          document.getElementById('stat-total-hours').textContent = data.total_hours + 'h';
          document.getElementById('stat-total-accounts').textContent = data.total_game_accounts;
        }
      } catch (e) { console.error(e); }
    }

    async function loadConfig() {
      try {
        const res = await fetch('/api/admin/config');
        const d = await res.json();
        document.getElementById('cfg-god').checked = d.feature_god_mode;
        document.getElementById('cfg-onehit').checked = d.feature_one_hit;
        document.getElementById('cfg-unlock').checked = d.feature_unlock_all;
        document.getElementById('cfg-fullshiny').checked = d.feature_full_shiny;
        document.getElementById('cfg-currency').checked = d.feature_currency;
        document.getElementById('cfg-autofarm').checked = d.feature_auto_farm;
        document.getElementById('cfg-autolevel').checked = d.feature_auto_levelup;
        document.getElementById('cfg-autocollect').checked = d.feature_auto_collect;
        document.getElementById('cfg-overnight').checked = d.feature_overnight;
        document.getElementById('cfg-autogacha').checked = d.feature_auto_gacha;
        document.getElementById('cfg-vietnamese').checked = d.feature_vietnamese;
        document.getElementById('cfg-maintenance').checked = d.maintenance_mode;
        document.getElementById('cfg-maintenance-msg').value = d.maintenance_msg || '';
        document.getElementById('cfg-announcement').value = d.announcement || '';
      } catch (e) { console.error(e); }
    }

    async function updateRemoteConfig() {
      const payload = {
        feature_god_mode: document.getElementById('cfg-god').checked,
        feature_one_hit: document.getElementById('cfg-onehit').checked,
        feature_unlock_all: document.getElementById('cfg-unlock').checked,
        feature_full_shiny: document.getElementById('cfg-fullshiny').checked,
        feature_currency: document.getElementById('cfg-currency').checked,
        feature_auto_farm: document.getElementById('cfg-autofarm').checked,
        feature_auto_levelup: document.getElementById('cfg-autolevel').checked,
        feature_auto_collect: document.getElementById('cfg-autocollect').checked,
        feature_overnight: document.getElementById('cfg-overnight').checked,
        feature_auto_gacha: document.getElementById('cfg-autogacha').checked,
        feature_vietnamese: document.getElementById('cfg-vietnamese').checked,
        maintenance_mode: document.getElementById('cfg-maintenance').checked,
        maintenance_msg: document.getElementById('cfg-maintenance-msg').value,
        announcement: document.getElementById('cfg-announcement').value
      };
      const res = await fetch('/api/admin/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const d = await res.json();
      if (d.success) showToast('Đã lưu cấu hình điều khiển từ xa!');
    }

    async function loadKeys() {
      try {
        const res = await fetch('/api/admin/keys');
        const data = await res.json();
        if (!data.success) return;

        const tb = document.getElementById('keys-table-body');
        if (data.keys.length === 0) {
          tb.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px;">Chưa có Key nào trong hệ thống. Hãy bấm Tạo Key Mới!</td></tr>';
          return;
        }

        tb.innerHTML = data.keys.map(k => {
          let statusBadge = '';
          if (!k.is_active) {
            statusBadge = '<span class="status-badge status-locked"><i class="fa-solid fa-lock"></i> Đã khoá</span>';
          } else if (k.is_expired) {
            statusBadge = '<span class="status-badge status-expired"><i class="fa-solid fa-circle-xmark"></i> Hết hạn</span>';
          } else {
            statusBadge = '<span class="status-badge status-active"><i class="fa-solid fa-circle-check"></i> Hoạt động</span>';
          }

          const onlineDot = k.is_online ? '<span class="online-indicator" title="Đang online 24/7"></span> ' : '';
          const clientType = k.bound_client_type ? (k.bound_client_type.includes('Kiwi') ? '<span style="color:#10b981"><i class="fa-brands fa-android"></i> ' + k.bound_client_type + '</span>' : '<span style="color:#38bdf8"><i class="fa-solid fa-desktop"></i> ' + k.bound_client_type + '</span>') : '<span style="color:#64748b">Chưa kích hoạt</span>';
          const gameAcc = k.last_game_acc ? '<b>' + k.last_game_acc + '</b>' : '<span style="color:#64748b">—</span>';
          const expText = k.expires_at || '<b style="color:#10b981">Vĩnh viễn</b>';

          return `
            <tr>
              <td>
                ${onlineDot}<span class="key-badge">${k.key_string}</span>
                <button onclick="copyText('${k.key_string}')" style="background:none; border:none; color:#64748b; cursor:pointer; margin-left:6px;" title="Copy key"><i class="fa-regular fa-copy"></i></button>
              </td>
              <td>${k.note || '—'}</td>
              <td>${statusBadge}</td>
              <td>${clientType}</td>
              <td>${gameAcc}</td>
              <td>${k.playtime_formatted}</td>
              <td>${expText}</td>
              <td>
                <div style="display:flex; gap:6px;">
                  <button class="btn btn-secondary" style="padding:4px 8px; font-size:12px;" onclick="extendKey('${k.key_string}')" title="Gia hạn +30 ngày"><i class="fa-solid fa-calendar-plus"></i> +30d</button>
                  <button class="btn btn-secondary" style="padding:4px 8px; font-size:12px;" onclick="resetHwid('${k.key_string}')" title="Gỡ thiết bị để đổi máy"><i class="fa-solid fa-arrows-rotate"></i> Reset</button>
                  <button class="btn ${k.is_active ? 'btn-secondary' : 'btn-success'}" style="padding:4px 8px; font-size:12px;" onclick="toggleKey('${k.key_string}')" title="${k.is_active ? 'Khóa key' : 'Mở khóa'}">
                    <i class="fa-solid ${k.is_active ? 'fa-lock' : 'fa-lock-open'}"></i>
                  </button>
                  <button class="btn btn-danger" style="padding:4px 8px; font-size:12px;" onclick="deleteKey('${k.key_string}')" title="Xóa vĩnh viễn"><i class="fa-solid fa-trash"></i></button>
                </div>
              </td>
            </tr>
          `;
        }).join('');
      } catch (e) { console.error(e); }
    }

    async function loadOnline() {
      try {
        const res = await fetch('/api/admin/online');
        const data = await res.json();
        if (!data.success) return;

        const tb = document.getElementById('online-table-body');
        if (data.online_list.length === 0) {
          tb.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px;">Hiện tại chưa có người chơi nào đang kết nối.</td></tr>';
          return;
        }

        tb.innerHTML = data.online_list.map(s => {
          const clientType = s.client_type.includes('Kiwi')
            ? '<span style="color:#10b981"><i class="fa-brands fa-android"></i> ' + s.client_type + '</span>'
            : '<span style="color:#38bdf8"><i class="fa-solid fa-desktop"></i> ' + s.client_type + '</span>';
          const hours = Math.round(s.total_playtime_sec / 36) / 100;
          return `
            <tr>
              <td><span class="online-indicator"></span> <b style="color:#34d399">Online</b></td>
              <td><b style="color:#fff">${s.game_account}</b></td>
              <td><span class="key-badge">${s.key_string}</span></td>
              <td>${clientType}</td>
              <td style="color:#94a3b8; font-family:monospace;">${s.ip_address}</td>
              <td>${hours}h</td>
              <td style="color:#94a3b8;">${s.last_heartbeat}</td>
            </tr>
          `;
        }).join('');
      } catch (e) { console.error(e); }
    }

    function refreshData() {
      loadStats();
      if (currentTab === 'keys') loadKeys();
      else loadOnline();
    }

    function copyText(txt) {
      navigator.clipboard.writeText(txt);
      showToast('Đã sao chép: ' + txt);
    }

    async function extendKey(k) {
      if (!confirm(`Bạn muốn gia hạn thêm 30 ngày cho key ${k}?`)) return;
      const res = await fetch('/api/admin/keys/extend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: k, days: 30 })
      });
      const d = await res.json();
      if (d.success) {
        showToast('Đã gia hạn thành công tới ' + d.new_expires_at);
        refreshData();
      }
    }

    async function resetHwid(k) {
      if (!confirm(`Gỡ thiết bị hiện tại của key ${k} để người dùng kích hoạt máy mới?`)) return;
      const res = await fetch('/api/admin/keys/reset-hwid', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: k })
      });
      const d = await res.json();
      if (d.success) {
        showToast('Đã reset thiết bị!');
        refreshData();
      }
    }

    async function toggleKey(k) {
      const res = await fetch('/api/admin/keys/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: k })
      });
      const d = await res.json();
      if (d.success) {
        showToast(d.is_active ? 'Đã mở khóa key' : 'Đã khóa key!');
        refreshData();
      }
    }

    async function deleteKey(k) {
      if (!confirm(`Bạn có chắc chắn muốn XOÁ VĨNH VIỄN key ${k}?`)) return;
      const res = await fetch('/api/admin/keys/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: k })
      });
      const d = await res.json();
      if (d.success) {
        showToast('Đã xóa key thành công');
        refreshData();
      }
    }

    function openCreateModal() { document.getElementById('create-modal').classList.add('show'); }
    function closeCreateModal() { document.getElementById('create-modal').classList.remove('show'); }

    async function submitCreateKey() {
      const payload = {
        duration_type: document.getElementById('modal-duration').value,
        note: document.getElementById('modal-note').value,
        custom_key: document.getElementById('modal-custom-key').value,
        quantity: document.getElementById('modal-quantity').value
      };
      const res = await fetch('/api/admin/keys/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const d = await res.json();
      if (d.success) {
        closeCreateModal();
        showToast(`Đã tạo thành công ${d.count} key!`);
        refreshData();
      }
    }

    // Init
    loadConfig();
    refreshData();
    setInterval(refreshData, 15000); // Tự động cập nhật số liệu mỗi 15 giây
  </script>
</body>
</html>
'''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    print(f"Server is running on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
