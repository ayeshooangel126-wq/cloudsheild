from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import sqlite3
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import os
import time
import threading

app = Flask(__name__)
app.secret_key = 'cloudshield_secret_2026'
DB_PATH = 'cloudshield.db'

# ============================================================
# DATABASE
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        verified INTEGER DEFAULT 0,
        terms_accepted INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        token TEXT,
        token_expiry INTEGER,
        device_info TEXT,
        ip_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_active TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_path TEXT,
        file_name TEXT,
        file_size INTEGER,
        file_type TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        message TEXT,
        location TEXT,
        severity TEXT,
        resolved INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()
    print("[+] Database ready!")

init_db()

# ============================================================
# EMAIL
# ============================================================
def send_verify_email(to_email, token):
    try:
        link = f"http://127.0.0.1:5000/verify/{token}"
        html = f"""
        <html>
        <body style="font-family:Arial;background:#0a1628;padding:40px;">
            <div style="max-width:500px;margin:auto;background:#132b5a;padding:30px;border-radius:16px;text-align:center;">
                <h1 style="color:#00d4ff;">🛡 CloudShield</h1>
                <p style="color:#c0d0e0;">Click below to verify your email:</p>
                <a href="{link}" style="display:inline-block;background:#00d4ff;color:#0a1628;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;margin:20px 0;">
                    ✅ Verify Account
                </a>
                <p style="color:#8899b0;font-size:12px;">Link expires in 10 minutes</p>
            </div>
        </body>
        </html>
        """
        msg = MIMEText(html, 'html')
        msg['Subject'] = 'CloudShield - Verify Your Email'
        msg['From'] = 'ayeshooangel126@gmail.com'
        msg['To'] = to_email
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('ayeshooangel126@gmail.com', 'ncpietlkypghvmvm')
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("[!] Email error:", e)
        return False

# ============================================================
# FULL FILE SCANNER
# ============================================================
def scan_user_files_full(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    folders_to_scan = [
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Pictures"),
        os.path.expanduser("~\\Videos"),
        os.path.expanduser("~\\Music"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
    ]
    
    extensions = [
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
        '.mp4', '.avi', '.mkv', '.mov', '.wmv',
        '.mp3', '.wav', '.flac', '.aac',
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '.exe', '.msi', '.bat', '.vbs', '.ps1', '.js', '.jar', '.scr'
    ]
    
    files_found = 0
    
    for folder in folders_to_scan:
        if os.path.exists(folder):
            for root, dirs, files in os.walk(folder):
                for file in files[:50]:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    if ext in extensions:
                        try:
                            file_size = os.path.getsize(file_path)
                            c.execute('SELECT * FROM files WHERE user_id = ? AND file_path = ?', (user_id, file_path))
                            if not c.fetchone():
                                c.execute('''INSERT INTO files (user_id, file_path, file_name, file_size, file_type) 
                                           VALUES (?, ?, ?, ?, ?)''',
                                           (user_id, file_path, file, file_size, ext))
                                files_found += 1
                        except:
                            pass
    
    conn.commit()
    conn.close()
    return files_found

def check_threats(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    threats = 0
    suspicious = ['.exe', '.bat', '.vbs', '.ps1', '.js', '.jar', '.scr']
    
    c.execute('SELECT file_path, file_name FROM files WHERE user_id = ?', (user_id,))
    files = c.fetchall()
    
    for file_path, file_name in files:
        ext = os.path.splitext(file_name)[1].lower()
        if ext in suspicious:
            c.execute('''INSERT INTO alerts (user_id, type, message, location, severity) 
                       VALUES (?, ?, ?, ?, ?)''',
                       (user_id, 'Suspicious File', f'File: {file_name}', file_path, 'HIGH'))
            threats += 1
    
    conn.commit()
    conn.close()
    return threats

# ============================================================
# BACKGROUND MONITORING
# ============================================================
def background_monitoring():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE verified = 1 AND is_blocked = 0')
            users = c.fetchall()
            conn.close()
            
            for user in users:
                scan_user_files_full(user[0])
                check_threats(user[0])
            
            time.sleep(120)
        except Exception as e:
            print("[!] Background error:", e)
            time.sleep(60)

threading.Thread(target=background_monitoring, daemon=True).start()
print("[+] Background monitoring started!")

# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/verify/<token>')
def verify_email(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE token = ? AND token_expiry > ?', (token, int(datetime.now().timestamp())))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return "<h1 style='color:red;'>❌ Invalid or Expired Link</h1><a href='/'>Go to Login</a>"
    
    c.execute('UPDATE users SET verified = 1, token = NULL, token_expiry = NULL WHERE id = ?', (user[0],))
    conn.commit()
    conn.close()
    
    session['user_id'] = user[0]
    session['user_email'] = user[1]
    
    return """
    <html>
    <body style="background:#0a1628;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;">
        <div style="background:#132b5a;padding:40px;border-radius:16px;text-align:center;">
            <h1 style="color:#00e676;">✅ Email Verified!</h1>
            <a href="/terms" style="display:inline-block;background:#00d4ff;color:#0a1628;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin-top:20px;">
                Accept Terms →
            </a>
        </div>
    </body>
    </html>
    """

@app.route('/terms')
def terms_page():
    if 'user_id' not in session:
        return redirect('/')
    return render_template('terms.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT is_blocked FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user and user[0] == 1:
        session.clear()
        return "<h1 style='color:red;'>❌ Your account has been blocked by admin</h1><a href='/'>Go to Login</a>"
    
    return render_template('dashboard.html', email=session.get('user_email', 'User'))

# ============================================================
# ADMIN
# ============================================================
@app.route('/admin_secret')
def admin_secret():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, email, device_info, ip_address, created_at, is_blocked FROM users WHERE verified = 1')
    users = c.fetchall()
    c.execute('SELECT id, user_id, file_name, file_size, file_type, created_at FROM files')
    files = c.fetchall()
    c.execute('SELECT user_id, type, message, severity, created_at FROM alerts WHERE resolved = 0')
    alerts = c.fetchall()
    conn.close()
    
    return render_template('admin_secret.html', users=users, files=files, alerts=alerts)

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/api/admin_login', methods=['POST'])
def api_admin_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if email == 'ayeshooangel126@gmail.com' and password == 'muskan$5':
        session['admin_logged_in'] = True
        return jsonify({'success': True, 'message': 'Admin login successful!'})
    return jsonify({'success': False, 'message': 'Invalid admin credentials!'})

@app.route('/api/admin_block_user', methods=['POST'])
def api_admin_block_user():
    if 'admin_logged_in' not in session:
        return jsonify({'success': False, 'message': 'Admin not logged in!'})
    data = request.json
    user_id = data.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET is_blocked = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'User blocked successfully!'})

@app.route('/api/admin_unblock_user', methods=['POST'])
def api_admin_unblock_user():
    if 'admin_logged_in' not in session:
        return jsonify({'success': False, 'message': 'Admin not logged in!'})
    data = request.json
    user_id = data.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET is_blocked = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'User unblocked successfully!'})

@app.route('/api/admin_user_files/<int:user_id>')
def api_admin_user_files(user_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, file_name, file_size, file_type, created_at FROM files WHERE user_id = ?', (user_id,))
    files = c.fetchall()
    conn.close()
    file_list = []
    for f in files:
        file_list.append({
            'id': f[0],
            'name': f[1],
            'size': f[2],
            'type': f[3],
            'created_at': f[4]
        })
    return jsonify({'success': True, 'files': file_list})

@app.route('/api/admin_view_file/<int:file_id>')
def api_admin_view_file(file_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT file_path, file_name FROM files WHERE id = ?', (file_id,))
    file = c.fetchone()
    conn.close()
    
    if not file:
        return jsonify({'error': 'File not found'}), 404
    
    file_path = file[0]
    file_name = file[1]
    
    # Check if file exists
    if not os.path.exists(file_path):
        return jsonify({'error': 'File does not exist on disk'}), 404
    
    # Image files - browser mein directly show
    if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
        return send_file(file_path, mimetype='image/jpeg')
    
    # PDF files
    elif file_name.lower().endswith('.pdf'):
        return send_file(file_path, mimetype='application/pdf')
    
    # Text files
    elif file_name.lower().endswith(('.txt', '.py', '.js', '.html', '.css', '.xml', '.json')):
        return send_file(file_path, mimetype='text/plain')
    
    # Video files
    elif file_name.lower().endswith(('.mp4', '.avi', '.mkv', '.mov')):
        return send_file(file_path, mimetype='video/mp4')
    
    # Audio files
    elif file_name.lower().endswith(('.mp3', '.wav', '.flac')):
        return send_file(file_path, mimetype='audio/mpeg')
    
    # Other files - download
    else:
        return send_file(file_path, as_attachment=True, download_name=file_name)

# ============================================================
# USER API
# ============================================================
@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if c.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Email already registered!'})
    hashed = hashlib.sha256(password.encode()).hexdigest()
    token = secrets.token_urlsafe(32)
    expiry = int(datetime.now().timestamp()) + 600
    device_info = request.headers.get('User-Agent', 'Unknown')
    ip_address = request.remote_addr
    c.execute('SELECT COUNT(*) FROM users')
    count = c.fetchone()[0]
    is_admin = 1 if count == 0 else 0
    c.execute('''INSERT INTO users (email, password, token, token_expiry, device_info, ip_address, is_admin) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
               (email, hashed, token, expiry, device_info, ip_address, is_admin))
    conn.commit()
    conn.close()
    send_verify_email(email, token)
    return jsonify({'success': True, 'message': 'Verification email sent! Check your Gmail inbox.'})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    user = c.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'success': False, 'message': 'User not found!'})
    if user[3] == 0:
        return jsonify({'success': False, 'message': 'Please verify your email first! Check Gmail.'})
    if user[4] == 0:
        return jsonify({'success': False, 'message': 'Please accept Terms & Policy first!'})
    if user[6] == 1:
        return jsonify({'success': False, 'message': 'Your account has been blocked by admin!'})
    if user[2] != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({'success': False, 'message': 'Invalid password!'})
    session['user_id'] = user[0]
    session['user_email'] = user[1]
    return jsonify({'success': True, 'message': 'Login successful!'})

@app.route('/api/accept_terms', methods=['POST'])
def api_accept_terms():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first!'})
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET terms_accepted = 1 WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Terms accepted!'})

@app.route('/api/dashboard_stats')
def api_dashboard_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    file_count = c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,)).fetchone()[0]
    alert_count = c.execute('SELECT COUNT(*) FROM alerts WHERE user_id = ? AND resolved = 0', (user_id,)).fetchone()[0]
    threat_count = c.execute('SELECT COUNT(*) FROM alerts WHERE user_id = ? AND severity = "HIGH" AND resolved = 0', (user_id,)).fetchone()[0]
    alerts = c.execute('SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (user_id,)).fetchall()
    conn.close()
    alert_list = []
    for alert in alerts:
        alert_list.append({
            'id': alert[0], 'type': alert[2], 'message': alert[3],
            'location': alert[4], 'severity': alert[5],
            'resolved': alert[6], 'created_at': alert[7]
        })
    return jsonify({
        'success': True,
        'stats': {
            'total_files': file_count,
            'alerts_count': alert_count,
            'threats_count': threat_count,
            'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        'alerts': alert_list
    })

@app.route('/api/scan_now', methods=['POST'])
def api_scan_now():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    scan_user_files_full(session['user_id'])
    threats = check_threats(session['user_id'])
    return jsonify({'success': True, 'message': f'Scan complete! Found {threats} threats.'})

@app.route('/api/resolve_alert', methods=['POST'])
def api_resolve_alert():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    alert_id = data.get('alert_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE alerts SET resolved = 1 WHERE id = ? AND user_id = ?', (alert_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Alert resolved!'})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)