#!/usr/bin/env python3
"""
Test de connexion sur tous les ports honeypot.
Génère de vrais événements visibles dans le dashboard Grafana.
  - SSH/Telnet  → cowrie.session.connect / login.failed / login.success
  - FTP         → logtype 2000
  - HTTP GET    → logtype 3000   (via urllib, suit les redirects)
  - HTTP POST   → logtype 3001   (tentative login NAS)
  - MySQL       → logtype 8001
  - RDP         → logtype 14001
  - VNC         → logtype 12001
"""

import socket
import time
import sys
import io
import urllib.request
import urllib.parse
import urllib.error

# Force UTF-8 sur Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

IP = "192.168.1.164"

def banner(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)

# --- SSH Cowrie (22) ---
banner("PORT 22 — SSH Cowrie (brute force via paramiko)")
try:
    import paramiko  # type: ignore
    creds = [("root","123456"),("root","password"),("admin","admin"),
             ("ubuntu","ubuntu"),("test","test"),("pi","raspberry")]
    for u,p in creds:
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(IP, port=22, username=u, password=p, timeout=3, banner_timeout=5)
            print(f"  [LOGIN OK] {u}/{p}")
            c.close()
        except paramiko.AuthenticationException:
            print(f"  [AUTH FAIL] {u}/{p}")
        except Exception as e:
            print(f"  [ERR] {u}/{p} — {e}")
except ImportError:
    print("  paramiko non installe — TCP test uniquement")
    try:
        s = socket.create_connection((IP, 22), timeout=3)
        data = s.recv(256)
        print(f"  SSH banner: {data.decode('latin1').strip()}")
        s.close()
    except Exception as e:
        print(f"  ERR: {e}")

# --- Telnet Cowrie (23) ---
banner("PORT 23 — Telnet Cowrie")
try:
    s = socket.create_connection((IP, 23), timeout=3)
    s.settimeout(2)
    try:
        data = s.recv(64)
        print(f"  Telnet banner: {data.hex()[:40]}")
    except socket.timeout:
        print("  Telnet connecte (pas de banner immediatement)")
    # Envoie user/pass telnet
    s.send(b"root\r\n")
    time.sleep(0.5)
    try:
        r = s.recv(64); print(f"  -> {r.decode('latin1','replace').strip()[:60]}")
    except: pass
    s.close()
except Exception as e:
    print(f"  ERR: {e}")

# --- FTP OpenCanary (21) ---
banner("PORT 21 — FTP OpenCanary")
for u,p in [("anonymous","anon@test.com"),("root","password"),("admin","admin123"),("ftp","ftp")]:
    try:
        s = socket.create_connection((IP, 21), timeout=3)
        s.settimeout(3)
        banner_data = s.recv(256).decode('latin1','replace').strip()
        print(f"  Banner: {banner_data[:50]}")
        s.send(f"USER {u}\r\n".encode()); time.sleep(0.3)
        r1 = s.recv(256).decode('latin1','replace').strip()
        s.send(f"PASS {p}\r\n".encode()); time.sleep(0.3)
        r2 = s.recv(256).decode('latin1','replace').strip()
        print(f"  {u}/{p} -> USER:{r1[:30]} | PASS:{r2[:30]}")
        s.close()
    except Exception as e:
        print(f"  ERR {u}: {e}")

# --- HTTP OpenCanary (80) ---
banner("PORT 80 — HTTP OpenCanary (logtype 3000 GET + 3001 POST login)")

# Désactiver les redirects automatiques pour voir les 302 ET suivre manuellement
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener_no_redir = urllib.request.build_opener(_NoRedirect)
opener_follow   = urllib.request.build_opener()  # suit les redirects → visite /index.html

# GET avec suivi de redirects → logtype 3000 (OpenCanary log la visite de /index.html)
for path in ["/", "/index.html", "/login", "/wp-login.php", "/phpmyadmin/"]:
    try:
        req = urllib.request.Request(
            f"http://{IP}{path}",
            headers={"User-Agent": "Mozilla/5.0 (compatible; scanner/1.0)", "Host": IP}
        )
        try:
            r = opener_follow.open(req, timeout=4)
            print(f"  [GET {r.getcode()}] {path}  (logtype 3000)")
            r.read(); r.close()
        except urllib.error.HTTPError as e:
            print(f"  [GET {e.code}] {path}")
    except Exception as e:
        print(f"  [ERR] GET {path}: {e}")
    time.sleep(0.3)

# POST login vers la page NAS → logtype 3001
http_creds = [("admin","admin"), ("admin","1234"), ("root","password"),
              ("user","user"), ("Admin","Admin123")]
for u, p in http_creds:
    try:
        data = urllib.parse.urlencode({"username": u, "password": p,
                                       "_nkParam": "1"}).encode()
        req = urllib.request.Request(
            f"http://{IP}/index.html",
            data=data,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": IP,
            }
        )
        try:
            r = opener_follow.open(req, timeout=4)
            print(f"  [POST {r.getcode()}] login {u}/{p}  (logtype 3001)")
            r.read(); r.close()
        except urllib.error.HTTPError as e:
            print(f"  [POST {e.code}] login {u}/{p}  (logtype 3001)")
    except Exception as e:
        print(f"  [ERR] POST {u}/{p}: {e}")
    time.sleep(0.5)

# --- MySQL OpenCanary (3306) ---
banner("PORT 3306 — MySQL OpenCanary")
try:
    s = socket.create_connection((IP, 3306), timeout=5)
    s.settimeout(3)
    data = s.recv(512)
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    print(f"  MySQL banner ({len(data)} bytes): {printable[:80]}")
    # Client Login Request v10 complet — déclenche logtype 8001
    # Longueur correcte : 4+4+1+23+5+1 = 38 bytes = 0x26
    body = (
        b'\x85\xa6\x0f\x00'           # capability flags
        b'\x00\x00\x00\x01'           # max packet size
        b'\x21'                        # charset utf8
        + b'\x00' * 23                # filler
        + b'root\x00'                 # username
        + b'\x00'                     # auth response length = 0
    )
    header = bytes([len(body) & 0xff, (len(body)>>8)&0xff, (len(body)>>16)&0xff, 1])
    s.send(header + body)
    time.sleep(0.5)
    try:
        r = s.recv(256)
        status = 'OK' if len(r) > 0 else 'no response'
        print(f"  MySQL auth attempt -> {len(r)} bytes ({status})")
    except socket.timeout:
        print("  MySQL: timeout (OK, event loggué)")
    s.close()
except Exception as e:
    print(f"  ERR: {e}")

# --- RDP OpenCanary (3389) ---
banner("PORT 3389 — RDP OpenCanary")
try:
    s = socket.create_connection((IP, 3389), timeout=3)
    # Envoie un x.224 connection request minimal
    pkt = bytes([
        0x03, 0x00, 0x00, 0x13,  # TPKT header
        0x0e,                     # length
        0xe0,                     # CR CDT
        0x00, 0x00, 0x00, 0x00, 0x00,  # DST-REF, SRC-REF, class
        0x01, 0x00, 0x08, 0x00, 0x00,  # RDP neg request
        0x00, 0x00, 0x00
    ])
    s.send(pkt)
    s.settimeout(3)
    try:
        r = s.recv(256)
        print(f"  RDP response ({len(r)} bytes): {r.hex()[:40]}")
    except socket.timeout:
        print("  RDP connecte (timeout response)")
    s.close()
except Exception as e:
    print(f"  ERR: {e}")

# --- VNC OpenCanary (5900) ---
banner("PORT 5900 — VNC OpenCanary")
try:
    s = socket.create_connection((IP, 5900), timeout=3)
    s.settimeout(3)
    data = s.recv(64)
    print(f"  VNC banner: {data.decode('ascii','replace').strip()}")
    # Réponse version
    s.send(b"RFB 003.008\n")
    time.sleep(0.5)
    try:
        auth_types = s.recv(64)
        print(f"  VNC auth types ({len(auth_types)} bytes): {auth_types.hex()}")
        # Sélectionner type 2 (VNC auth) pour déclencher logtype 12001
        if len(auth_types) >= 2 and auth_types[0] > 0:
            s.send(bytes([2]))   # sélectionner VNC auth
            time.sleep(0.5)
            challenge = s.recv(16)   # challenge 16 bytes
            s.send(b'\x00' * 16)     # réponse bidon
            time.sleep(0.5)
            result = s.recv(4)
            print(f"  VNC auth result: {result.hex()} (event 12001 loggué)")
    except socket.timeout:
        print("  VNC: timeout après version (OK)")
    except Exception as e:
        print(f"  VNC auth: {e}")
    s.close()
except Exception as e:
    print(f"  ERR: {e}")

# --- Résumé PostgreSQL ---
banner("VERIFICATION EVENEMENTS EN BASE")
print("  Attente 10s pour que le parser OpenCanary traite les logs...")
time.sleep(10)
try:
    import paramiko as _paramiko  # type: ignore
    _c = _paramiko.SSHClient()
    _c.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
    _c.connect(IP, port=2222, username='ubuntu', password='ubuntu', timeout=10)
    def _run(cmd):
        _, o, e = _c.exec_command(cmd, timeout=15)
        return (o.read()+e.read()).decode('utf-8','replace').strip()
    result = _run(
        "PGPASSWORD=honeypot123 psql -U honeypot -h localhost -d honeypot -c "
        "'SELECT source, event_type, dst_port, count(*) AS n "
        "FROM events GROUP BY 1,2,3 ORDER BY 1,3;'"
    )
    print(result)
    _c.close()
except Exception as e:
    print(f"  DB ERR: {e}")

print("\n" + "="*50)
print("  TESTS TERMINES")
print("="*50 + "\n")
