# Procédure d'installation complète — Honeypot VM

> **Installation rapide :**
> ```bash
> wget -O install.sh https://raw.githubusercontent.com/j0k3r91/HoneyPot/master/install.sh
> sudo bash install.sh
> ```
> Ce document détaille chaque étape pour une installation manuelle ou la compréhension du système.

> **Objectif :** Installer from scratch un honeypot avec Cowrie, OpenCanary, PostgreSQL et Grafana.  
> **OS recommandé :** Ubuntu 24.04 LTS — 1 vCPU minimum, 1 GB RAM, 20 GB disque  

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Préparation OS + UFW](#2-préparation-os)
3. [PostgreSQL](#3-postgresql)
4. [Cowrie (SSH/Telnet honeypot)](#4-cowrie-sshtelnet-honeypot)
5. [Plugin pglog (Cowrie → PostgreSQL)](#5-plugin-pglog-cowrie--postgresql)
6. [OpenCanary (FTP/HTTP/MySQL/RDP/VNC)](#6-opencanary-ftphttpmysqlrdpvnc)
7. [honeypot-parser (OpenCanary → PostgreSQL)](#7-honeypot-parser-opencanary--postgresql)
8. [Grafana](#8-grafana)
9. [Dashboard Grafana](#9-dashboard-grafana)
10. [Vérification finale](#10-vérification-finale)
11. [Référence — Infos de connexion](#11-référence--infos-de-connexion)

---

## 1. Prérequis

### Accès SSH
- Port SSH d'administration : **2222** (redirigé vers le port 22 système — Cowrie écoute le port 22 standard)
- Clé SSH : votre clé privée
- Connexion : `ssh -i "<votre-cle>.key" -p 2222 <user>@<IP>`

> **Important :** Cowrie occupe le port 22. Le vrai SSH d'administration doit tourner sur un port différent (2222).

### Changer le port SSH système avant l'installation de Cowrie

```bash
sudo nano /etc/ssh/sshd_config
# Modifier : Port 22  →  Port 2222
sudo systemctl restart ssh
```

---

## 2. Préparation OS

```bash
sudo apt update && sudo apt upgrade -y

# Paquets nécessaires
sudo apt install -y \
    python3 python3-pip python3-venv python3-dev \
    git curl wget net-tools \
    postgresql postgresql-contrib \
    build-essential libssl-dev libffi-dev

# Créer l'utilisateur Cowrie (dédié, sans accès sudo)
sudo adduser --disabled-password cowrie
```

### Pare-feu UFW

```bash
# UFW est pré-installé sur Ubuntu 24.04
ufw default deny incoming
ufw default allow outgoing

# SSH d'administration (remplacer 2222 par votre port)
ufw allow 2222/tcp   # SSH admin

# Ports honeypot Cowrie
ufw allow 22/tcp     # SSH honeypot
ufw allow 23/tcp     # Telnet honeypot

# Ports honeypot OpenCanary
ufw allow 21/tcp     # FTP
ufw allow 80/tcp     # HTTP
ufw allow 3306/tcp   # MySQL
ufw allow 3389/tcp   # RDP
ufw allow 5900/tcp   # VNC

# Grafana (dashboard de supervision)
ufw allow 3000/tcp

ufw --force enable
ufw status
```

---

## 3. PostgreSQL

### Installation et démarrage

```bash
# PostgreSQL est installé par apt ci-dessus
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### Création de la base et de l'utilisateur

```bash
sudo -u postgres psql << 'EOF'
CREATE USER honeypot WITH PASSWORD 'VOTRE_MDP_PG';   -- Remplacer par un mot de passe fort
CREATE DATABASE honeypot OWNER honeypot;
\q
EOF
```

### Création du schéma

```bash
sudo -u postgres psql -d honeypot << 'EOF'
CREATE TABLE events (
    id         SERIAL PRIMARY KEY,
    timestamp  TEXT,
    ts         BIGINT,
    source     TEXT,
    src_ip     TEXT,
    dst_port   INTEGER,
    event_type TEXT,
    username   TEXT,
    password   TEXT,
    message    TEXT
);

-- Contrainte de déduplication
ALTER TABLE events
    ADD CONSTRAINT events_timestamp_src_ip_event_type_key
    UNIQUE (timestamp, src_ip, event_type);

-- Index de performance
CREATE INDEX idx_events_ts         ON events (ts DESC);
CREATE INDEX idx_events_ts_type    ON events (ts DESC, event_type);
CREATE INDEX idx_events_ts_ip      ON events (ts DESC, src_ip);
CREATE INDEX idx_events_src_ip     ON events (src_ip);
CREATE INDEX idx_events_event_type ON events (event_type);
CREATE INDEX idx_events_port       ON events (dst_port) WHERE dst_port > 0;
CREATE INDEX idx_events_login_ok   ON events (ts DESC)
    WHERE event_type = 'cowrie.login.success';

VACUUM ANALYZE events;
EOF
```

### Configuration pg_hba.conf

Le fichier `/etc/postgresql/16/main/pg_hba.conf` doit contenir :

```
local   all   postgres                peer
local   all   all                     md5
host    all   all   127.0.0.1/32      md5
host    all   all   ::1/128           md5
```

Après modification :

```bash
sudo systemctl reload postgresql
```

---

## 4. Cowrie (SSH/Telnet honeypot)

### Installation

```bash
sudo -u cowrie bash << 'EOF'
cd /home/cowrie

# Cloner le dépôt
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Créer l'environnement virtuel
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Installer psycopg2 pour le plugin pglog
pip install psycopg2-binary

deactivate
EOF
```

### Configuration cowrie.cfg

```bash
sudo -u cowrie cp /home/cowrie/cowrie/etc/cowrie.cfg.dist /home/cowrie/cowrie/etc/cowrie.cfg
```

Éditer `/home/cowrie/cowrie/etc/cowrie.cfg` — sections clés :

```ini
[honeypot]
hostname = svr04
log_path = var/log/cowrie

[ssh]
enabled = true
listen_port = 22
listen_endpoints = tcp:22:interface=0.0.0.0

[telnet]
enabled = true
listen_port = 23
listen_endpoints = tcp:23:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[output_pglog]
enabled = true
host = localhost
database = honeypot
username = honeypot
password = VOTRE_MDP_PG
port = 5432
debug = false
```

> Tous les autres `[output_*]` restent `enabled = false`.

### Service systemd Cowrie

Créer `/etc/systemd/system/cowrie.service` :

```ini
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment=PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
Type=forking
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie
```

---

## 5. Plugin pglog (Cowrie → PostgreSQL)

Ce plugin écrit les événements Cowrie directement dans la table `events` de PostgreSQL via Twisted/adbapi (latence ~0 ms).

### Déploiement

Créer `/home/cowrie/cowrie/src/cowrie/output/pglog.py` :

```python
"""
Custom Cowrie output plugin — writes directly into the unified 'events' table.
Place at: /home/cowrie/cowrie/src/cowrie/output/pglog.py
"""
from __future__ import annotations
import datetime
from twisted.enterprise import adbapi
from twisted.python import log
import cowrie.core.output
from cowrie.core.config import CowrieConfig

TRACKED_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.client.version",
}

INSERT_SQL = """
    INSERT INTO events
        (timestamp, ts, source, src_ip, dst_port, event_type, username, password, message)
    VALUES (%s, %s, 'cowrie', %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, src_ip, event_type) DO NOTHING
"""


class Output(cowrie.core.output.Output):
    debug: bool = False

    def start(self):
        self.debug = CowrieConfig.getboolean("output_pglog", "debug", fallback=False)
        port = CowrieConfig.getint("output_pglog", "port", fallback=5432)
        self.db = adbapi.ConnectionPool(
            "psycopg2",
            host=CowrieConfig.get("output_pglog", "host"),
            database=CowrieConfig.get("output_pglog", "database"),
            user=CowrieConfig.get("output_pglog", "username"),
            password=CowrieConfig.get("output_pglog", "password", raw=True),
            port=port,
            cp_min=1,
            cp_max=1,
        )
        log.msg("output_pglog: connected to PostgreSQL honeypot events table")

    def stop(self):
        self.db.close()

    def sqlerror(self, error):
        log.msg(f"output_pglog: DB error: {error.value.args!r}")

    def _format_ts(self, t: float):
        dt = datetime.datetime.utcfromtimestamp(t)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
        return iso, int(t * 1000)

    @staticmethod
    def _clean(s):
        """Retire les caractères NUL (0x00) qui font planter psycopg2."""
        if s is None:
            return None
        return str(s).replace("\x00", "")

    def _insert(self, timestamp_str, ts_ms, event_type, src_ip, dst_port,
                username=None, password=None, message=None):
        d = self.db.runOperation(
            INSERT_SQL,
            (timestamp_str, ts_ms,
             self._clean(src_ip), dst_port, event_type,
             self._clean(username), self._clean(password), self._clean(message)),
        )
        d.addErrback(self.sqlerror)

    def write(self, event):
        event_id = event.get("eventid", "")
        if event_id not in TRACKED_EVENTS:
            return
        t = event.get("time", 0)
        ts_str, ts_ms = self._format_ts(t)
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port", 22)

        if event_id == "cowrie.session.connect":
            self._insert(ts_str, ts_ms, event_id, src_ip, dst_port)
        elif event_id in ("cowrie.login.failed", "cowrie.login.success"):
            self._insert(ts_str, ts_ms, event_id, src_ip, dst_port,
                         username=event.get("username"), password=event.get("password"))
        elif event_id in ("cowrie.command.input", "cowrie.command.failed"):
            self._insert(ts_str, ts_ms, event_id, src_ip, dst_port,
                         message=event.get("input"))
        elif event_id == "cowrie.session.file_download":
            self._insert(ts_str, ts_ms, event_id, src_ip, dst_port,
                         message=event.get("url", event.get("shasum", "")))
        elif event_id == "cowrie.client.version":
            self._insert(ts_str, ts_ms, event_id, src_ip, dst_port,
                         message=str(event.get("version", "")))
```

```bash
# Fixer les permissions
sudo chown cowrie:cowrie /home/cowrie/cowrie/src/cowrie/output/pglog.py

# Redémarrer Cowrie pour charger le plugin
sudo systemctl restart cowrie

# Vérifier que le plugin est chargé
sudo journalctl -u cowrie -n 20 | grep pglog
```

> **Note :** Le nom du fichier doit impérativement être `pglog.py` car Cowrie utilise `x.split("_")[1]` pour extraire le nom du module depuis la section `[output_pglog]`.

---

## 6. OpenCanary (FTP/HTTP/MySQL/RDP/VNC)

### Installation

```bash
# Créer l'environnement virtuel OpenCanary
python3 -m venv /home/ubuntu/opencanary-env
source /home/ubuntu/opencanary-env/bin/activate
pip install opencanary
deactivate
```

### Configuration

Créer `/etc/opencanaryd/opencanary.conf` :

```bash
sudo mkdir -p /etc/opencanaryd
sudo tee /etc/opencanaryd/opencanary.conf > /dev/null << 'EOF'
{
    "device.node_id": "opencanary-1",
    "device.name": "mon-honeypot",
    "device.desc": "Honeypot",
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": { "format": "%(message)s" }
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary.log"
                }
            }
        }
    },
    "ftp.enabled": true,
    "ftp.port": 21,
    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.4.41 (Ubuntu)",
    "http.skin": "nasLogin",
    "https.enabled": false,
    "https.port": 443,
    "httpproxy.enabled": false,
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.5.43-0ubuntu0.14.04.1",
    "mysql.log_connection_made": false,
    "rdp.enabled": true,
    "rdp.port": 3389,
    "redis.enabled": false,
    "smb.enabled": false,
    "ssh.enabled": false,
    "telnet.enabled": false,
    "vnc.enabled": true,
    "vnc.port": 5900,
    "mssql.enabled": false,
    "ntp.enabled": false,
    "sip.enabled": false,
    "snmp.enabled": false,
    "tftp.enabled": false,
    "portscan.enabled": false
}
EOF
```

### Service systemd OpenCanary

Créer `/etc/systemd/system/opencanary.service` :

```ini
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu
ExecStart=/home/ubuntu/opencanary-env/bin/opencanaryd --dev
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable opencanary
sudo systemctl start opencanary
```

### Logtypes OpenCanary

| Logtype | Protocole | Port |
|---|---|---|
| `1001` | SSH | 22 |
| `2000` | FTP | 21 |
| `3000` | HTTP GET | 80 |
| `3001` | HTTP POST (login) | 80 |
| `8001` | MySQL | 3306 |
| `9001` | Telnet | 23 |
| `12001` | VNC | 5900 |
| `14001` | RDP | 3389 |

---

## 7. honeypot-parser (OpenCanary → PostgreSQL)

Ce service lit les logs d'OpenCanary via inotify et les insère en base de données.

### Environnement virtuel dédié

```bash
python3 -m venv /home/ubuntu/honeypot-parser-env
/home/ubuntu/honeypot-parser-env/bin/pip install psycopg2-binary
```

### Script parser

Créer `/opt/honeypot-to-postgres.py` :

```python
#!/usr/bin/env python3
"""
honeypot-to-postgres.py  —  inotify-driven log parser (OpenCanary only)
Cowrie events are handled directly by the output_pglog Cowrie plugin.
"""
import ctypes, json, os, select, struct
from datetime import datetime, timezone
import psycopg2, psycopg2.extras

PG_CONFIG = {
    "host": "localhost", "dbname": "honeypot",
    "user": "honeypot", "password": "VOTRE_MDP_PG",
}
BATCH_SIZE     = 500
OPENCANARY_LOG = "/var/log/opencanary.log"
POSITION_FILE  = "/var/lib/honeypot-pos.json"

IN_MODIFY = 0x00000002; IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080; IN_CREATE = 0x00000100
WATCH_MASK = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
_EV = struct.Struct("iIII")
_libc = ctypes.CDLL("libc.so.6", use_errno=True)

def _inotify_init():
    fd = _libc.inotify_init1(0o4000)
    if fd < 0: raise OSError(ctypes.get_errno(), "inotify_init1 failed")
    return fd

def _inotify_add_watch(ifd, path, mask=WATCH_MASK):
    wd = _libc.inotify_add_watch(ifd, path.encode(), mask)
    if wd < 0: raise OSError(ctypes.get_errno(), f"inotify_add_watch({path}) failed")
    return wd

def _drain(ifd):
    try:
        while True: os.read(ifd, 4096)
    except BlockingIOError: pass

_conn = None

def get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(**PG_CONFIG); _conn.autocommit = False
    return _conn

def parse_ts(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return ts_str, int(dt.timestamp() * 1000)
    except Exception:
        now = datetime.now(tz=timezone.utc)
        return now.isoformat(), int(now.timestamp() * 1000)

def insert_batch(batch):
    if not batch: return
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, """
                INSERT INTO events (timestamp, ts, source, src_ip, dst_port,
                    event_type, username, password, message)
                VALUES %s ON CONFLICT DO NOTHING
            """, batch)
        conn.commit()
    except Exception as e:
        print(f"[ERROR] insert_batch: {e}")
        try: _conn.rollback()
        except Exception: pass

def check_rotation(filepath, last_pos):
    try:
        if last_pos > os.path.getsize(filepath): return 0
    except Exception: pass
    return last_pos

def parse_file(filepath, parser_func, last_pos):
    if not os.path.exists(filepath): return last_pos
    last_pos = check_rotation(filepath, last_pos)
    batch = []
    with open(filepath, "r", errors="replace") as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                event = parser_func(line)
                if event: batch.append(event)
                if len(batch) >= BATCH_SIZE:
                    insert_batch(batch); batch = []
            except Exception as e:
                print(f"[WARN] parse error: {e}")
        insert_batch(batch)
        return f.tell()

def parse_opencanary(line):
    e = json.loads(line)
    ts_str, ts_ms = parse_ts(e.get("local_time", ""))
    logdata = e.get("logdata", {})
    username = logdata.get("USERNAME") if isinstance(logdata, dict) else None
    password = logdata.get("PASSWORD") if isinstance(logdata, dict) else None
    return (ts_str, ts_ms, "opencanary", e.get("src_host"), e.get("dst_port"),
            str(e.get("logtype")), username, password, json.dumps(logdata))

def load_positions():
    try:
        with open(POSITION_FILE) as f: return json.load(f).get("opencanary", 0)
    except Exception: return 0

def save_positions(pos):
    with open(POSITION_FILE, "w") as f:
        json.dump({"cowrie": 0, "opencanary": pos}, f)

if __name__ == "__main__":
    opencanary_pos = load_positions()
    ifd = _inotify_init()
    oc_dir = os.path.dirname(OPENCANARY_LOG)
    try:
        _inotify_add_watch(ifd, oc_dir)
        print(f"[INFO] Watching {oc_dir}")
    except OSError as e:
        print(f"[WARN] Cannot watch {oc_dir}: {e}")
    print("Starting honeypot parser (OpenCanary only, inotify mode) …")
    opencanary_pos = parse_file(OPENCANARY_LOG, parse_opencanary, opencanary_pos)
    save_positions(opencanary_pos); _drain(ifd)
    while True:
        ready = select.select([ifd], [], [], 5.0)[0]
        if ready: _drain(ifd)
        opencanary_pos = parse_file(OPENCANARY_LOG, parse_opencanary, opencanary_pos)
        save_positions(opencanary_pos)
```

### Service systemd honeypot-parser

Créer `/etc/systemd/system/honeypot-parser.service` :

```ini
[Unit]
Description=Honeypot Log Parser
After=network.target postgresql.service

[Service]
Type=simple
ExecStart=/home/ubuntu/honeypot-parser-env/bin/python3 /opt/honeypot-to-postgres.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot-parser
sudo systemctl start honeypot-parser
```

---

## 8. Grafana

### Installation

```bash
# Ajouter le dépôt Grafana officiel
wget -q -O - https://apt.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install -y grafana

sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

> Version installée : **Grafana 12** (la dernière stable disponible sur le dépôt officiel au moment de l'installation)

### Configuration HTTPS (certificat auto-signé)

Le script `install.sh` configure automatiquement HTTPS avec un certificat auto-signé (valide 10 ans).
Si vous configurez manuellement, voici les commandes équivalentes :

```bash
# Générer le certificat
sudo mkdir -p /etc/grafana/certs
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/grafana/certs/grafana.key \
    -out    /etc/grafana/certs/grafana.crt \
    -subj   "/CN=grafana-honeypot/O=HoneyPot/C=FR"
sudo chown -R grafana:grafana /etc/grafana/certs
sudo chmod 600 /etc/grafana/certs/grafana.key
```

Éditer `/etc/grafana/grafana.ini` :

```ini
[server]
protocol   = https
http_port  = 3000
cert_file  = /etc/grafana/certs/grafana.crt
cert_key   = /etc/grafana/certs/grafana.key
```

```bash
sudo systemctl restart grafana-server
```

> **Note :** Le certificat est auto-signé — le navigateur affichera une alerte à ignorer (`proceed anyway`).

### Ajouter la datasource PostgreSQL

Dans Grafana UI :  
**Settings → Data Sources → Add → PostgreSQL**

| Champ | Valeur |
|---|---|
| Host | `localhost:5432` |
| Database | `honeypot` |
| User | `honeypot` |
| Password | votre mot de passe PostgreSQL |
| SSL Mode | `disable` |
| PostgreSQL version | `16` |

Ou via l'API Grafana :

```bash
curl -k -s -u admin:admin \
  -X POST https://localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PostgreSQL",
    "type": "grafana-postgresql-datasource",
    "url": "localhost:5432",
    "database": "honeypot",
    "user": "honeypot",
    "secureJsonData": {"password": "VOTRE_MDP_PG"},
    "jsonData": {"sslmode": "disable", "postgresVersion": 1600}
  }'
```

**Changer le mot de passe admin :** Grafana UI → Profile → Change Password → choisir un mot de passe fort

---

## 9. Dashboard Grafana

### Déploiement automatique

Le dashboard est déployé **automatiquement** par `install.sh` (étape 11/12). Il n'y a rien à faire manuellement après l'installation.

Pour **re-déployer** le dashboard manuellement (après une réinstallation Grafana par exemple) :

```bash
# Depuis le serveur :
GF_PASS=votre-mdp-grafana PG_PASS=votre-mdp-pg \
  /home/<user>/honeypot-parser-env/bin/python3 /tmp/optimize.py
```

### Contenu du dashboard (20 panels)

| # | Panel | Type | Description |
|---|---|---|---|
| 1 | 🔌 Total Connexions | Stat | Nombre total d'événements sur la période sélectionnée |
| 2 | 🌍 IPs Uniques | Stat | Nombre d'IPs distinctes ayant attaqué |
| 3 | ⚠️ Logins Réussis ALARME | Stat | `cowrie.login.success` — rouge dès 1 |
| 4 | 💻 Commandes Exécutées | Stat | `cowrie.command.input` |
| 5 | 🗂️ Fichiers Uploadés (Malware) | Stat | `cowrie.session.file_upload` |
| 6 | 🚫 Logins Échoués | Stat | `cowrie.login.failed` + OpenCanary SSH |
| 7 | 📈 Activité dans le Temps — Toutes Sources | Timeseries | SSH/Telnet, FTP, HTTP, MySQL, RDP, VNC par bucket temporel |
| 8 | 🏆 Top 10 IPs Attaquantes | Barchart | IP les plus actives |
| 9 | 🔀 Répartition par Protocole | Piechart (donut) | SSH/Telnet Cowrie + FTP/HTTP/MySQL/RDP/VNC OpenCanary |
| 10 | 🔓 Logins Réussis par IP | Barchart | IP avec `cowrie.login.success` |
| 11 | 💻 Top Commandes Exécutées | Barchart | Commandes les plus fréquentes |
| 12 | 👤 Top Usernames Essayés | Barchart | Identifiants les plus testés |
| 13 | 🔑 Top Passwords Essayés | Barchart | Mots de passe les plus testés |
| 14 | 📋 Journal des Attaques en Temps Réel | Table | 300 derniers événements toutes sources |
| 15 | 💻 Commandes Exécutées par les Attaquants | Table | Détail des commandes shell |
| 16 | 🗂️ Fichiers Uploadés (Malware/Backdoors) | Table | Détail des uploads |
| — | 🔍 Surveillance des Ports Honeypot | Row | Séparateur de section |
| 17 | 🛡️ Connexions par Port Honeypot | Barchart | Comptage par port (21/22/23/80/3306/3389/5900) |
| 18 | 📡 Activité par Port dans le Temps | Timeseries | Évolution des connexions par port |
| 19 | 📊 Récap — Tous les Ports Honeypot | Table | Total, IPs uniques, 1ère/dernière attaque par port |

### Variable dashboard `$port`

Le dashboard expose un filtre de port configurable via le sélecteur en haut. Valeurs disponibles :

| Valeur | Filtre |
|---|---|
| `All` | Tous les ports (valeur `0`) |
| `SSH (22)` | Port 22 — Cowrie |
| `Telnet (23)` | Port 23 — Cowrie |
| `FTP (21)` | Port 21 — OpenCanary |
| `HTTP (80)` | Port 80 — OpenCanary |
| `MySQL (3306)` | Port 3306 — OpenCanary |
| `RDP (3389)` | Port 3389 — OpenCanary |
| `VNC (5900)` | Port 5900 — OpenCanary |

---

## 10. Vérification finale

```bash
# Statut de tous les services
systemctl status cowrie opencanary honeypot-parser grafana-server postgresql

# Vérifier les événements en base
sudo -u postgres psql -d honeypot -c "SELECT source, event_type, COUNT(*) FROM events GROUP BY source, event_type ORDER BY count DESC LIMIT 20;"

# Vérifier que Cowrie insère bien (pglog)
sudo journalctl -u cowrie -n 20 | grep pglog

# Vérifier le parser OpenCanary
sudo journalctl -u honeypot-parser -n 20

# Ports en écoute
sudo ss -tlnp | grep -E ':22|:23|:21|:80|:3000|:3306|:3389|:5432|:5900'
```

### Résultat attendu

```
PORT   SERVICE         PROCESSUS
22     SSH Cowrie       twistd (cowrie)
23     Telnet Cowrie    twistd (cowrie)
21     FTP OpenCanary   twistd (opencanary)
80     HTTP OpenCanary  twistd (opencanary)
3306   MySQL OpenCanary twistd (opencanary)
3389   RDP OpenCanary   twistd (opencanary)
5432   PostgreSQL       postgres
5900   VNC OpenCanary   twistd (opencanary)
3000   Grafana (HTTPS)  grafana
2222   SSH admin        sshd
```

---

## 11. Référence — Infos de connexion

| Service | Détail |
|---|---|
| **Serveur** | Votre IP publique |
| **SSH admin** | `ssh -p 2222 <user>@<IP>` |
| **PostgreSQL** | `localhost:5432` · db=`honeypot` · user=`honeypot` · pass=`VOTRE_MDP_PG` |
| **Grafana** | `https://<IP>:3000` · `admin` / votre mot de passe Grafana *(cert auto-signé)* |
| **Grafana datasource UID** | auto-détecté par `optimize.py` |
| **Dashboard UID** | `honeypot-v4` |
| **Dashboard nom** | `🍯 Honeypot Dashboard` |
| **Dashboard refresh** | 5 secondes |

### Environnements Python

| Env | Chemin | Usage |
|---|---|---|
| `cowrie-env` | `/home/cowrie/cowrie/cowrie-env/` | Cowrie + plugin pglog |
| `opencanary-env` | `/home/ubuntu/opencanary-env/` | OpenCanary |
| `honeypot-parser-env` | `/home/ubuntu/honeypot-parser-env/` | honeypot-parser |

### Fichiers importants sur le serveur

| Fichier | Rôle |
|---|---|
| `/home/cowrie/cowrie/etc/cowrie.cfg` | Config Cowrie |
| `/home/cowrie/cowrie/src/cowrie/output/pglog.py` | Plugin PG Cowrie |
| `/etc/opencanaryd/opencanary.conf` | Config OpenCanary |
| `/var/log/opencanary.log` | Logs OpenCanary (parsés par honeypot-parser) |
| `/opt/honeypot-to-postgres.py` | Script parser OpenCanary |
| `/var/lib/honeypot-pos.json` | Position lecture log OpenCanary |
| `/etc/grafana/grafana.ini` | Config Grafana |
| `/etc/systemd/system/cowrie.service` | Service Cowrie |
| `/etc/systemd/system/opencanary.service` | Service OpenCanary |
| `/etc/systemd/system/honeypot-parser.service` | Service parser |

---

## Architecture finale

```
Internet
    │
    ├── :22  (Cowrie SSH)  ──► cowrie-env/twistd ──► plugin pglog
    ├── :23  (Cowrie Telnet) ─► cowrie-env/twistd ──► plugin pglog ──┐
    │                                                                  │
    ├── :21  (FTP)         ──► opencanary-env/twistd ──────────────  │
    ├── :80  (HTTP)        ──► opencanary-env/twistd ──┐             │
    ├── :3306 (MySQL)      ──► opencanary-env/twistd ──┤             │
    ├── :3389 (RDP)        ──► opencanary-env/twistd ──┤             │
    └── :5900 (VNC)        ──► opencanary-env/twistd ──┘             │
                                        │                              │
                             /var/log/opencanary.log                   │
                                        │ inotify (~0ms)               │ adbapi (~0ms)
                             honeypot-parser.service ─────────────────┤
                                                                        │
                                                   PostgreSQL 16 ◄─────┘
                                                   db: honeypot
                                                   table: events
                                                        │
                                                   Grafana 12.4.1
                                                   https://:3000
                                                   20 panels / 5s refresh

    :2222 ──► SSH administration (sshd)
```
