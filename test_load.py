#!/usr/bin/env python3
"""
Test de charge étendu — 5 minutes de trafic honeyot réaliste.
Lance des vagues répétées de connexions sur tous les ports honeypot
pour générer suffisamment de données dans le dashboard Grafana.
"""

import socket
import time
import sys
import io
import random
import urllib.request
import urllib.parse
import urllib.error

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

IP       = "192.168.1.164"
DURATION = 300  # 5 minutes

# ── Credentials pools ──────────────────────────────────────────────────────────
SSH_CREDS = [
    ("root","123456"), ("root","password"), ("root","toor"), ("root","admin"),
    ("admin","admin"), ("admin","password"), ("admin","123456"),
    ("ubuntu","ubuntu"), ("pi","raspberry"), ("test","test"),
    ("user","user"), ("guest","guest"), ("oracle","oracle"),
    ("postgres","postgres"), ("deploy","deploy"),
]
FTP_CREDS = [
    ("anonymous","anon@test.com"), ("root","password"), ("admin","admin123"),
    ("ftp","ftp"), ("user","user123"), ("upload","upload"),
]
HTTP_CREDS = [
    ("admin","admin"), ("admin","1234"), ("root","password"),
    ("user","user"), ("Admin","Admin123"), ("admin","admin123"),
]
HTTP_PATHS = ["/", "/index.html", "/login", "/wp-login.php",
              "/phpmyadmin/", "/admin/", "/manager/"]

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None

opener = urllib.request.build_opener()

# ── Helpers ────────────────────────────────────────────────────────────────────
def ok(msg):  print(f"  ✓ {msg}")
def err(msg): print(f"  ✗ {msg}")

def elapsed(start):
    s = int(time.time() - start)
    return f"{s//60}m{s%60:02d}s"

# ── Attack functions ───────────────────────────────────────────────────────────
def attack_ssh():
    try:
        import paramiko
        u, p = random.choice(SSH_CREDS)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(IP, port=22, username=u, password=p, timeout=3, banner_timeout=5)
        ok(f"SSH LOGIN OK {u}/{p}")
        c.close()
    except Exception as ex:
        msg = str(ex)
        if "Authentication" in msg:
            ok(f"SSH fail {u}/{p}")
        else:
            err(f"SSH {ex}")

def attack_telnet():
    try:
        u, p = random.choice(SSH_CREDS)
        s = socket.create_connection((IP, 23), timeout=3)
        s.settimeout(2)
        s.recv(64)
        s.send(f"{u}\r\n".encode()); time.sleep(0.3)
        try: s.recv(64)
        except: pass
        s.send(f"{p}\r\n".encode()); time.sleep(0.2)
        try: s.recv(64)
        except: pass
        s.close()
        ok(f"Telnet {u}/{p}")
    except Exception as ex:
        err(f"Telnet {ex}")

def attack_ftp():
    try:
        u, p = random.choice(FTP_CREDS)
        s = socket.create_connection((IP, 21), timeout=3)
        s.settimeout(3)
        s.recv(256)
        s.send(f"USER {u}\r\n".encode()); time.sleep(0.2); s.recv(256)
        s.send(f"PASS {p}\r\n".encode()); time.sleep(0.2)
        try: s.recv(256)
        except: pass
        s.close()
        ok(f"FTP {u}/{p}")
    except Exception as ex:
        err(f"FTP {ex}")

def attack_http():
    try:
        path = random.choice(HTTP_PATHS)
        req = urllib.request.Request(
            f"http://{IP}{path}",
            headers={"User-Agent": "Mozilla/5.0 (scanner)", "Host": IP}
        )
        try:
            r = opener.open(req, timeout=4)
            ok(f"HTTP GET {path} → {r.getcode()}")
            r.read(); r.close()
        except urllib.error.HTTPError as e:
            ok(f"HTTP GET {path} → {e.code}")
    except Exception as ex:
        err(f"HTTP GET {ex}")

def attack_http_post():
    try:
        u, p = random.choice(HTTP_CREDS)
        data = urllib.parse.urlencode({"username": u, "password": p}).encode()
        req = urllib.request.Request(
            f"http://{IP}/index.html", data=data,
            headers={"User-Agent": "Mozilla/5.0",
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Host": IP}
        )
        try:
            r = opener.open(req, timeout=4)
            ok(f"HTTP POST {u}/{p} → {r.getcode()}")
            r.read(); r.close()
        except urllib.error.HTTPError as e:
            ok(f"HTTP POST {u}/{p} → {e.code}")
    except Exception as ex:
        err(f"HTTP POST {ex}")

def attack_mysql():
    try:
        s = socket.create_connection((IP, 3306), timeout=5)
        s.settimeout(3)
        s.recv(512)
        body = b'\x85\xa6\x0f\x00\x00\x00\x00\x01\x21' + b'\x00'*23 + b'root\x00\x00'
        s.send(bytes([len(body)&0xff,(len(body)>>8)&0xff,(len(body)>>16)&0xff,1]) + body)
        time.sleep(0.3)
        try: s.recv(256)
        except: pass
        s.close()
        ok("MySQL auth attempt")
    except Exception as ex:
        err(f"MySQL {ex}")

def attack_rdp():
    try:
        s = socket.create_connection((IP, 3389), timeout=3)
        pkt = bytes([0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,0x00,0x00,0x00])
        s.send(pkt)
        s.settimeout(2)
        try: s.recv(256)
        except: pass
        s.close()
        ok("RDP connection attempt")
    except Exception as ex:
        err(f"RDP {ex}")

def attack_vnc():
    try:
        s = socket.create_connection((IP, 5900), timeout=3)
        s.settimeout(3)
        try: banner = s.recv(32); ok(f"VNC banner: {banner.decode('latin1','replace').strip()[:30]}")
        except: pass
        # Réponse protocole VNC
        try:
            s.send(b"RFB 003.008\n")
            time.sleep(0.3)
            s.recv(64)
        except: pass
        s.close()
    except Exception as ex:
        err(f"VNC {ex}")

# ── Attack schedule ─────────────────────────────────────────────────────────────
# Chaque vague = liste de (fonction, poids)
ATTACKS = [
    (attack_ssh,        5),  # SSH est le plus fréquent
    (attack_telnet,     2),
    (attack_ftp,        3),
    (attack_http,       3),
    (attack_http_post,  2),
    (attack_mysql,      2),
    (attack_rdp,        2),
    (attack_vnc,        1),
]

funcs  = [f for f, w in ATTACKS]
weights = [w for f, w in ATTACKS]

# ── Main loop ──────────────────────────────────────────────────────────────────
start = time.time()
wave  = 0

print(f"\n{'='*60}")
print(f"  TEST CHARGE HONEYPOT — {DURATION}s ({DURATION//60} min)")
print(f"  Cible : {IP}")
print(f"{'='*60}\n")

while True:
    remaining = DURATION - (time.time() - start)
    if remaining <= 0:
        break

    wave += 1
    wave_size = random.randint(4, 8)
    chosen = random.choices(funcs, weights=weights, k=wave_size)

    print(f"\n── Vague {wave}  [{elapsed(start)} / {DURATION//60}m00s restant: {int(remaining)}s] ──")
    for fn in chosen:
        fn()
        time.sleep(random.uniform(0.3, 1.2))

    # Pause inter-vague
    pause = random.uniform(5, 15)
    print(f"  ... pause {pause:.0f}s")
    time.sleep(pause)

total = time.time() - start
print(f"\n{'='*60}")
print(f"  TERMINÉ — {wave} vagues en {total:.0f}s")
print(f"  Vérifiez le dashboard : https://{IP}:3000")
print(f"{'='*60}\n")
