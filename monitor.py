from flask import Flask, render_template_string, request, redirect, session
import subprocess
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "itsat-secure-key"

client_name = "PSG Insure (STA)"
REFRESH_RATE = 30

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def make_hash(password):
    return generate_password_hash(password, method="pbkdf2:sha256")

def check_ping(host):
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

def db():
    return sqlite3.connect("monitor.db")

def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS systems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip TEXT,
        role TEXT,
        priority TEXT,
        maintenance INTEGER DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        system_name TEXT,
        ip TEXT,
        status TEXT,
        checked_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        system_name TEXT,
        ip TEXT,
        role TEXT,
        priority TEXT,
        status TEXT,
        started_at TEXT,
        resolved_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        action TEXT,
        logged_at TEXT
    )
    """)

    c.execute("SELECT * FROM users WHERE email=?", ("sizwe@itsat.co.za",))
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            ("sizwe@itsat.co.za", make_hash("1234"), "admin")
        )

    c.execute("SELECT COUNT(*) FROM systems")
    if c.fetchone()[0] == 0:
        default_systems = [
            ("PABX Server", "172.25.100.6", "PABX", "Critical", 0),
            ("Hypervisor", "172.25.100.9", "Virtualization Host", "Critical", 0),
            ("Print Server", "172.25.100.20", "Print / File", "High", 0),
            ("Device 1", "10.0.10.10", "Network", "High", 0),
            ("Device 2", "10.0.10.11", "Network", "High", 0),
            ("Device 3", "10.0.10.65", "Network", "Medium", 0),
            ("Public Link", "154.127.127.30", "Internet", "Critical", 0),
            ("Gateway", "172.25.30.1", "Firewall", "Critical", 0),
        ]
        c.executemany(
            "INSERT INTO systems (name, ip, role, priority, maintenance) VALUES (?, ?, ?, ?, ?)",
            default_systems
        )

    conn.commit()
    conn.close()

init_db()

def audit(user, action):
    conn = db()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (user_email, action, logged_at) VALUES (?, ?, ?)", (user, action, now()))
    conn.commit()
    conn.close()

def log_check(name, ip, status):
    conn = db()
    c = conn.cursor()
    c.execute("INSERT INTO checks (system_name, ip, status, checked_at) VALUES (?, ?, ?, ?)", (name, ip, status, now()))
    conn.commit()
    conn.close()

def handle_incident(system, status):
    conn = db()
    c = conn.cursor()

    c.execute("SELECT id FROM incidents WHERE ip=? AND status='Open'", (system["ip"],))
    open_incident = c.fetchone()

    if status == "Offline" and not open_incident:
        c.execute("""
        INSERT INTO incidents (system_name, ip, role, priority, status, started_at, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (system["name"], system["ip"], system["role"], system["priority"], "Open", now(), None))

        print("🚨 INCIDENT OPENED")
        print(f"Client: {client_name}")
        print(f"System: {system['name']}")
        print(f"IP: {system['ip']}")
        print(f"Priority: {system['priority']}")
        print(f"Time: {now()}")
        print("-----------------------------")

    elif status == "Online" and open_incident:
        c.execute("UPDATE incidents SET status='Resolved', resolved_at=? WHERE id=?", (now(), open_incident[0]))

        print("✅ INCIDENT RESOLVED")
        print(f"Client: {client_name}")
        print(f"System: {system['name']}")
        print(f"IP: {system['ip']}")
        print(f"Time: {now()}")
        print("-----------------------------")

    conn.commit()
    conn.close()

def get_systems():
    conn = db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM systems ORDER BY id")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_today_uptime():
    conn = db()
    c = conn.cursor()
    today_start = datetime.now().strftime("%Y-%m-%d 00:00:00")
    c.execute("""
    SELECT COUNT(*), SUM(CASE WHEN status='Online' THEN 1 ELSE 0 END)
    FROM checks
    WHERE checked_at >= ?
    """, (today_start,))
    total, online = c.fetchone()
    conn.close()

    if not total:
        return 100.0

    return round((online / total) * 100, 1)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT password, role FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["user"] = email
            session["role"] = user[1]
            audit(email, "Logged in")
            return redirect("/")
        else:
            error = "Invalid login"

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>IT Sat Monitor Login</title>
<style>
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial; background:#070707; color:white; display:flex; align-items:center; justify-content:center; height:100vh; }
.card { background:#111; padding:36px; border-radius:18px; width:360px; text-align:center; border:1px solid #252525; box-shadow:0 20px 80px rgba(0,0,0,.55); }
h2 { color:#ff9f1c; font-size:28px; }
p { color:#aaa; }
input { width:100%; padding:14px; margin:8px 0; background:#1d1d1d; border:1px solid #333; color:white; border-radius:10px; box-sizing:border-box; }
button { width:100%; padding:14px; background:#ff9f1c; border:none; border-radius:10px; font-weight:bold; cursor:pointer; }
.error { color:#ff4d4d; font-size:13px; margin-top:12px; }
</style>
</head>
<body>
<div class="card">
    <h2>IT Sat Monitor</h2>
    <p>Technology that cares.</p>
    <form method="POST">
        <input name="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Login</button>
    </form>
    <div class="error">{{ error }}</div>
</div>
</body>
</html>
""", error=error)

@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    systems = get_systems()
    results = []
    online = 0
    offline = 0
    maintenance_count = 0

    for system in systems:
        if system["maintenance"] == 1:
            status = "Maintenance"
            is_online = True
            maintenance_count += 1
        else:
            is_online = check_ping(system["ip"])
            status = "Online" if is_online else "Offline"

        log_check(system["name"], system["ip"], status)

        if system["maintenance"] != 1:
            handle_incident(system, status)

        results.append({**system, "status": status, "is_online": is_online})

        if status == "Online":
            online += 1
        elif status == "Offline":
            offline += 1

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>IT Sat Monitor</title>
<meta http-equiv="refresh" content="{{ refresh }}">
<style>
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial; background:radial-gradient(circle at top,#171717,#050505); color:#eee; padding:20px; }
.container { max-width:1280px; margin:auto; }
.top { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; border-bottom:1px solid #222; padding-bottom:16px; }
.brand { color:#ff9f1c; font-weight:900; font-size:30px; }
.badge { background:#151515; border:1px solid #2a2a2a; border-radius:24px; padding:7px 13px; font-size:13px; color:#bbb; }
.nav a { color:#ff9f1c; text-decoration:none; margin-left:16px; font-size:14px; font-weight:800; }
.client { font-size:26px; font-weight:900; margin-bottom:4px; }
.sub { font-size:13px; color:#888; margin-bottom:14px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-bottom:14px; }
.stat { background:#151515; border:1px solid #262626; border-radius:14px; padding:13px 15px; }
.stat-num { font-size:28px; font-weight:900; line-height:1; }
.stat-label { color:#aaa; font-size:13px; margin-top:5px; }
.green { color:#00ff88; }
.red { color:#ff4d4d; }
.amber { color:#ff9f1c; }
.blue { color:#68a8ff; }
.table { border:1px solid #242424; border-radius:14px; overflow:hidden; background:#111; }
.row { display:grid; grid-template-columns:2fr 1fr 1fr 1fr; align-items:center; padding:9px 14px; border-bottom:1px solid #242424; font-size:14px; }
.row:last-child { border-bottom:none; }
.header { background:#151515; color:#999; font-size:12px; font-weight:900; text-transform:uppercase; letter-spacing:.04em; }
.system-name { font-weight:900; }
.ip { color:#777; font-size:12px; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; background:#00ff88; }
.dot-red { background:#ff4d4d; }
.dot-amber { background:#ff9f1c; }
.status { text-align:right; font-weight:900; }
.footer { color:#666; font-size:12px; text-align:center; margin-top:12px; }
</style>
</head>
<body>
<div class="container">
    <div class="top">
        <div class="brand">Technology that cares.</div>
        <div>
            <span class="badge">{{ session.user }} · {{ session.role }} · <span class="green">Online</span></span>
            <span class="nav">
                <a href="/systems">Systems</a>
                <a href="/reports">Reports</a>
                <a href="/incidents">Incidents</a>
                <a href="/audit">Audit</a>
                <a href="/logout">Logout</a>
            </span>
        </div>
    </div>

    <div class="client">{{ client }}</div>
    <div class="sub">Last checked {{ time }} · Auto-refresh {{ refresh }}s</div>

    <div class="stats">
        <div class="stat"><div class="stat-num green">{{ online }}</div><div class="stat-label">Online</div></div>
        <div class="stat"><div class="stat-num red">{{ offline }}</div><div class="stat-label">Offline</div></div>
        <div class="stat"><div class="stat-num blue">{{ maintenance }}</div><div class="stat-label">Maintenance</div></div>
        <div class="stat"><div class="stat-num">{{ total }}</div><div class="stat-label">Systems</div></div>
        <div class="stat"><div class="stat-num amber">{{ uptime }}%</div><div class="stat-label">Today Uptime</div></div>
    </div>

    <div class="table">
        <div class="row header">
            <div>System</div>
            <div>Role</div>
            <div>Priority</div>
            <div>Status</div>
        </div>

        {% for i in results %}
        <div class="row">
            <div>
                <span class="dot {{ 'dot-red' if i.status == 'Offline' else 'dot-amber' if i.status == 'Maintenance' else '' }}"></span>
                <span class="system-name">{{ i.name }}</span><br>
                <span class="ip">{{ i.ip }}</span>
            </div>
            <div>{{ i.role }}</div>
            <div class="{{ 'red' if i.priority == 'Critical' else 'amber' if i.priority == 'High' else '' }}">{{ i.priority }}</div>
            <div class="status {{ 'green' if i.status == 'Online' else 'amber' if i.status == 'Maintenance' else 'red' }}">{{ i.status }}</div>
        </div>
        {% endfor %}
    </div>

    <div class="footer">IT Sat Monitor v1.3 · Editable systems enabled</div>
</div>
</body>
</html>
""", results=results, online=online, offline=offline, maintenance=maintenance_count,
     total=len(systems), uptime=get_today_uptime(), client=client_name,
     time=datetime.now().strftime("%H:%M:%S"), refresh=REFRESH_RATE)

@app.route("/systems")
def systems_page():
    if "user" not in session:
        return redirect("/login")

    systems = get_systems()

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>Systems</title>
<style>
body { margin:0; font-family:Arial; background:#0a0a0a; color:white; padding:24px; }
.container { max-width:1100px; margin:auto; }
a { color:#ff9f1c; text-decoration:none; font-weight:bold; }
h1 { color:#ff9f1c; }
form, .card { background:#151515; border:1px solid #242424; padding:14px; margin-bottom:10px; border-radius:10px; }
input, select { padding:10px; margin:4px; background:#222; color:white; border:1px solid #333; border-radius:8px; }
button { padding:10px 14px; background:#ff9f1c; border:none; border-radius:8px; font-weight:bold; cursor:pointer; }
.delete { color:#ff4d4d; margin-left:10px; }
</style>
</head>
<body>
<div class="container">
<a href="/">← Back</a>
<h1>Manage Systems</h1>

<form method="POST" action="/systems/add">
    <input name="name" placeholder="System name" required>
    <input name="ip" placeholder="IP / Host" required>
    <input name="role" placeholder="Role" required>
    <select name="priority">
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
    </select>
    <button>Add System</button>
</form>

{% for s in systems %}
<div class="card">
    <form method="POST" action="/systems/edit/{{ s.id }}">
        <input name="name" value="{{ s.name }}">
        <input name="ip" value="{{ s.ip }}">
        <input name="role" value="{{ s.role }}">
        <select name="priority">
            <option {{ 'selected' if s.priority == 'Critical' else '' }}>Critical</option>
            <option {{ 'selected' if s.priority == 'High' else '' }}>High</option>
            <option {{ 'selected' if s.priority == 'Medium' else '' }}>Medium</option>
            <option {{ 'selected' if s.priority == 'Low' else '' }}>Low</option>
        </select>
        <select name="maintenance">
            <option value="0" {{ 'selected' if s.maintenance == 0 else '' }}>Active</option>
            <option value="1" {{ 'selected' if s.maintenance == 1 else '' }}>Maintenance</option>
        </select>
        <button>Save</button>
        <a class="delete" href="/systems/delete/{{ s.id }}">Delete</a>
    </form>
</div>
{% endfor %}
</div>
</body>
</html>
""", systems=systems)

@app.route("/systems/add", methods=["POST"])
def add_system():
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO systems (name, ip, role, priority, maintenance) VALUES (?, ?, ?, ?, ?)",
        (
            request.form.get("name"),
            request.form.get("ip"),
            request.form.get("role"),
            request.form.get("priority"),
            0
        )
    )
    conn.commit()
    conn.close()

    audit(session["user"], "Added system")
    return redirect("/systems")

@app.route("/systems/edit/<int:id>", methods=["POST"])
def edit_system(id):
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute("""
    UPDATE systems
    SET name=?, ip=?, role=?, priority=?, maintenance=?
    WHERE id=?
    """, (
        request.form.get("name"),
        request.form.get("ip"),
        request.form.get("role"),
        request.form.get("priority"),
        int(request.form.get("maintenance")),
        id
    ))
    conn.commit()
    conn.close()

    audit(session["user"], f"Edited system ID {id}")
    return redirect("/systems")

@app.route("/systems/delete/<int:id>")
def delete_system(id):
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM systems WHERE id=?", (id,))
    conn.commit()
    conn.close()

    audit(session["user"], f"Deleted system ID {id}")
    return redirect("/systems")

@app.route("/incidents")
def incidents():
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute("""
    SELECT system_name, ip, role, priority, status, started_at, resolved_at
    FROM incidents
    ORDER BY id DESC
    LIMIT 100
    """)
    rows = c.fetchall()
    conn.close()

    return render_template_string("""
<html><body style="background:#0a0a0a;color:white;font-family:Arial;padding:24px;">
<a style="color:#ff9f1c" href="/">← Back</a>
<h1 style="color:#ff9f1c">Incident Log</h1>
{% for row in rows %}
<div style="background:#151515;border:1px solid #242424;padding:15px;margin-bottom:10px;border-radius:12px;">
<strong>{{ row[0] }}</strong> · {{ row[1] }} · {{ row[2] }} · {{ row[3] }}<br>
Status: {{ row[4] }}<br>
Started: {{ row[5] }}<br>
Resolved: {{ row[6] if row[6] else "Not yet resolved" }}
</div>
{% endfor %}
</body></html>
""", rows=rows)

@app.route("/reports")
def reports():
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute("""
    SELECT system_name, COUNT(*), SUM(CASE WHEN status='Online' THEN 1 ELSE 0 END)
    FROM checks
    GROUP BY system_name
    """)
    rows = c.fetchall()
    conn.close()

    data = []
    for name, total, online in rows:
        uptime = round((online / total) * 100, 1) if total else 0
        data.append((name, total, uptime))

    return render_template_string("""
<html><body style="background:#0a0a0a;color:white;font-family:Arial;padding:24px;">
<a style="color:#ff9f1c" href="/">← Back</a>
<h1 style="color:#ff9f1c">Reports</h1>
{% for name, total, uptime in data %}
<div style="background:#151515;border:1px solid #242424;padding:15px;margin-bottom:10px;border-radius:12px;display:flex;justify-content:space-between;">
<div><strong>{{ name }}</strong><br>{{ total }} checks</div>
<div>{{ uptime }}%</div>
</div>
{% endfor %}
</body></html>
""", data=data)

@app.route("/audit")
def audit_page():
    if "user" not in session:
        return redirect("/login")

    conn = db()
    c = conn.cursor()
    c.execute("SELECT user_email, action, logged_at FROM audit_log ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()

    return render_template_string("""
<html><body style="background:#0a0a0a;color:white;font-family:Arial;padding:24px;">
<a style="color:#ff9f1c" href="/">← Back</a>
<h1 style="color:#ff9f1c">Audit Log</h1>
{% for row in rows %}
<div style="background:#151515;border:1px solid #242424;padding:14px;margin-bottom:8px;border-radius:10px;">
<strong>{{ row[0] }}</strong> · {{ row[1] }}<br>{{ row[2] }}
</div>
{% endfor %}
</body></html>
""", rows=rows)

@app.route("/logout")
def logout():
    if "user" in session:
        audit(session["user"], "Logged out")
    session.clear()
    return redirect("/login")

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
