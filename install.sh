#!/usr/bin/env bash
# ==============================================================================
#  HONEYPOT INSTALL SCRIPT
#  Installe : Cowrie (SSH/Telnet) + OpenCanary (FTP/HTTP/MySQL/RDP/VNC)
#             + PostgreSQL 16 + Grafana 12 + honeypot-parser
#  OS cible  : Ubuntu 24.04 LTS
#  Usage     : sudo bash install.sh
# ==============================================================================

set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ── Vérification root ─────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Ce script doit être exécuté en root : sudo bash $0"

# ==============================================================================
#  CONFIGURATION FIXE (non interactive)
# ==============================================================================
SSH_ADMIN_PORT=2222
PG_USER="honeypot"
PG_DB="honeypot"
COWRIE_USER="cowrie"
COWRIE_HOME="/home/cowrie/cowrie"
COWRIE_ENV="${COWRIE_HOME}/cowrie-env"
REAL_USER="${SUDO_USER:-ubuntu}"
OPENCANARY_ENV="/home/${REAL_USER}/opencanary-env"
PARSER_ENV="/home/${REAL_USER}/honeypot-parser-env"
GRAFANA_PORT=3000
# ==============================================================================

# ── Helper saisie mot de passe (double confirmation) ─────────────────────────
prompt_password() {
    local VAR_NAME="$1"
    local LABEL="$2"
    local MIN_LEN=8
    local P1 P2
    # </dev/tty : indispensable quand le script est exécuté via curl | bash
    # (stdin est alors le pipe, pas le terminal)
    while true; do
        read -rsp "  ${LABEL} : " P1 < /dev/tty; echo ""
        [[ ${#P1} -ge $MIN_LEN ]] || { warn "Minimum ${MIN_LEN} caractères requis."; continue; }
        read -rsp "  Confirmer ${LABEL} : " P2 < /dev/tty; echo ""
        [[ "$P1" == "$P2" ]] && break || warn "Les mots de passe ne correspondent pas, réessayez."
    done
    printf -v "$VAR_NAME" '%s' "$P1"
}

# ── Helper saisie texte avec valeur par défaut ────────────────────────────────
prompt_input() {
    local VAR_NAME="$1"
    local LABEL="$2"
    local DEFAULT="$3"
    local VALUE
    read -rp "  ${LABEL} [${DEFAULT}] : " VALUE < /dev/tty
    printf -v "$VAR_NAME" '%s' "${VALUE:-$DEFAULT}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        HONEYPOT INSTALLATION SCRIPT             ║${NC}"
echo -e "${BOLD}║  Cowrie + OpenCanary + PostgreSQL + Grafana      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo -e "${BOLD}${BLUE}━━  Configuration interactive  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Port SSH admin
prompt_input SSH_ADMIN_PORT "Port SSH d'administration (Cowrie prendra le port 22)" "2222"

# Hostname Cowrie
prompt_input COWRIE_HOSTNAME "Hostname affiché dans le faux shell Cowrie" "svr04"

# Mot de passe PostgreSQL
echo ""
info "Mot de passe pour l'utilisateur PostgreSQL '${PG_USER}' :"
prompt_password PG_PASS "Mot de passe PostgreSQL"

# Mot de passe Grafana
echo ""
info "Mot de passe pour l'admin Grafana :"
prompt_password GRAFANA_ADMIN_PASS "Mot de passe Grafana admin"

# Récap avant de lancer
echo ""
echo -e "${BOLD}${BLUE}━━  Récapitulatif  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Port SSH admin     : ${CYAN}${SSH_ADMIN_PORT}${NC}"
echo -e "  Hostname Cowrie    : ${CYAN}${COWRIE_HOSTNAME}${NC}"
echo -e "  Utilisateur courant: ${CYAN}${REAL_USER}${NC}"
echo -e "  PostgreSQL user    : ${CYAN}${PG_USER}${NC} / ${CYAN}[mot de passe saisi]${NC}"
echo -e "  Grafana admin      : ${CYAN}admin${NC} / ${CYAN}[mot de passe saisi]${NC}"
echo -e "  Port Grafana       : ${CYAN}${GRAFANA_PORT}${NC}"
echo ""
warn "Le port SSH va passer sur ${SSH_ADMIN_PORT}. Assurez-vous d'avoir accès à ce port."
echo ""
read -rp "Lancer l'installation ? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Installation annulée."

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "1/12 — Mise à jour système + paquets"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    git curl wget net-tools \
    postgresql postgresql-contrib \
    build-essential libssl-dev libffi-dev \
    libpq-dev ufw openssl authbind

ok "Paquets installés"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "2/12 — Port SSH d'administration → ${SSH_ADMIN_PORT}"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSHD_CFG="/etc/ssh/sshd_config"

# Sauvegarder la config originale si pas encore fait
[[ ! -f "${SSHD_CFG}.orig" ]] && cp "${SSHD_CFG}" "${SSHD_CFG}.orig"

# Ubuntu 24.04 : désactiver le socket activation (ssh.socket écoute sur 22 par défaut
# et prend la priorité sur sshd_config Port). On bascule sur ssh.service classique.
if systemctl is-enabled ssh.socket &>/dev/null; then
    systemctl disable --now ssh.socket || true
    systemctl enable ssh.service || true
    ok "Socket activation SSH désactivé → ssh.service activé"
fi

# Remplacer ou ajouter le port
if grep -qE '^Port ' "${SSHD_CFG}"; then
    sed -i "s/^Port .*/Port ${SSH_ADMIN_PORT}/" "${SSHD_CFG}"
else
    sed -i "1a Port ${SSH_ADMIN_PORT}" "${SSHD_CFG}"
fi

# Activer l'authentification par mot de passe (désactivée par défaut sur Ubuntu 24.04)
if grep -qE '^#?PasswordAuthentication' "${SSHD_CFG}"; then
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "${SSHD_CFG}"
else
    echo "PasswordAuthentication yes" >> "${SSHD_CFG}"
fi

systemctl restart ssh
ok "SSH admin déplacé sur le port ${SSH_ADMIN_PORT} (PasswordAuthentication activé)"
warn "Reconnectez-vous sur le port ${SSH_ADMIN_PORT} si vous êtes déconnecté."

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "3/12 — Pare-feu UFW"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ⚠  Avertissement anti-lockout
# Le port SSH admin (${SSH_ADMIN_PORT}) sera ouvert AVANT l'activation d'UFW.
# Assurez-vous que votre fournisseur cloud n'a pas de firewall externe qui
# bloquerait ce port (AWS Security Groups, règles VPS, etc.)
warn "Port SSH admin à ouvrir : ${SSH_ADMIN_PORT}/tcp — vérifiez aussi le firewall de votre fournisseur cloud"

# Réinitialiser les règles existantes et appliquer la politique par défaut
# Note : reset désactive UFW temporairement (pas de coupure de session active)
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH d'administration (port choisi par l'utilisateur) — TOUJOURS EN PREMIER
ufw allow "${SSH_ADMIN_PORT}/tcp" comment "SSH admin"

# Ports honeypot Cowrie
ufw allow 22/tcp  comment "Cowrie SSH"
ufw allow 23/tcp  comment "Cowrie Telnet"

# Ports honeypot OpenCanary
ufw allow 21/tcp   comment "OpenCanary FTP"
ufw allow 80/tcp   comment "OpenCanary HTTP"
ufw allow 3306/tcp comment "OpenCanary MySQL"
ufw allow 3389/tcp comment "OpenCanary RDP"
ufw allow 5900/tcp comment "OpenCanary VNC"

# Grafana (dashboard de supervision — restreindre à votre IP en production)
ufw allow 3000/tcp comment "Grafana"

# Activer UFW sans demande interactive
ufw --force enable

ok "Pare-feu UFW activé — $(ufw status | grep -c ALLOW) règles configurées"
info "Règles actives :"
ufw status | grep -E 'ALLOW|DENY' | sed 's/^/    /'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "4/12 — PostgreSQL : base de données + schéma"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
systemctl enable postgresql
systemctl start postgresql

# Créer le rôle et la base (idempotent)
sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${PG_USER}') THEN
    CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASS}';
  END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${PG_DB} OWNER ${PG_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${PG_DB}')
\gexec
SQL

# Créer le schéma + index (idempotent)
sudo -u postgres psql -d "${PG_DB}" -v ON_ERROR_STOP=0 <<'SQL'
CREATE TABLE IF NOT EXISTS events (
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

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'events_timestamp_src_ip_event_type_key'
  ) THEN
    ALTER TABLE events
      ADD CONSTRAINT events_timestamp_src_ip_event_type_key
      UNIQUE (timestamp, src_ip, event_type);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_events_ts         ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ts_type    ON events (ts DESC, event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts_ip      ON events (ts DESC, src_ip);
CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_port       ON events (dst_port) WHERE dst_port > 0;
CREATE INDEX IF NOT EXISTS idx_events_login_ok   ON events (ts DESC)
    WHERE event_type = 'cowrie.login.success';

VACUUM ANALYZE events;
SQL

# GRANT séparé : le bloc précédent est <<'SQL' (pas d'expansion), on utilise un nouveau psql
sudo -u postgres psql -d "${PG_DB}" -v ON_ERROR_STOP=0 <<SQL
GRANT ALL PRIVILEGES ON TABLE events TO ${PG_USER};
GRANT USAGE, SELECT ON SEQUENCE events_id_seq TO ${PG_USER};
SQL

ok "Base PostgreSQL '${PG_DB}' prête avec 9 index"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "5/12 — Cowrie (honeypot SSH/Telnet)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Créer l'user cowrie s'il n'existe pas
if ! id "${COWRIE_USER}" &>/dev/null; then
    adduser --disabled-password --gecos "" "${COWRIE_USER}"
    ok "Utilisateur '${COWRIE_USER}' créé"
fi

# Cloner si pas déjà fait
if [[ ! -d "${COWRIE_HOME}/.git" ]]; then
    sudo -u "${COWRIE_USER}" git clone https://github.com/cowrie/cowrie.git "${COWRIE_HOME}"
    ok "Cowrie cloné dans ${COWRIE_HOME}"
else
    ok "Cowrie déjà présent, mise à jour git..."
    sudo -u "${COWRIE_USER}" git -C "${COWRIE_HOME}" pull --ff-only || true
fi

# Créer le virtualenv si absent
if [[ ! -x "${COWRIE_ENV}/bin/python3" ]]; then
    sudo -u "${COWRIE_USER}" python3 -m venv "${COWRIE_ENV}"
    ok "Virtualenv cowrie-env créé"
fi

# Installer les dépendances
sudo -u "${COWRIE_USER}" "${COWRIE_ENV}/bin/pip" install -q --upgrade pip
sudo -u "${COWRIE_USER}" "${COWRIE_ENV}/bin/pip" install -q -r "${COWRIE_HOME}/requirements.txt"
# Installer Cowrie comme package (enregistre le plugin twistd "cowrie")
sudo -u "${COWRIE_USER}" "${COWRIE_ENV}/bin/pip" install -q -e "${COWRIE_HOME}"
sudo -u "${COWRIE_USER}" "${COWRIE_ENV}/bin/pip" install -q psycopg2-binary
ok "Dépendances Cowrie installées (+ plugin twistd + psycopg2-binary)"

# Générer cowrie.cfg depuis le template
[[ ! -f "${COWRIE_HOME}/etc/cowrie.cfg.dist" ]] && die "cowrie.cfg.dist introuvable — vérifiez le clone"
cp "${COWRIE_HOME}/etc/cowrie.cfg.dist" "${COWRIE_HOME}/etc/cowrie.cfg"
chown "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}/etc/cowrie.cfg"

# Activer SSH + Telnet, plug pglog
python3 - <<PYEOF
import re, sys

cfg_path = "${COWRIE_HOME}/etc/cowrie.cfg"
with open(cfg_path) as f:
    content = f.read()

# Section [honeypot] — hostname
content = re.sub(r'(?m)^#?\s*hostname\s*=.*', 'hostname = ${COWRIE_HOSTNAME}', content)

# Section [ssh]
content = re.sub(r'(?ms)(^\[ssh\].*?)(enabled\s*=\s*\w+)', r'\1enabled = true', content)
content = re.sub(r'(?ms)(^\[ssh\].*?)(listen_port\s*=\s*\S+)', r'\1listen_port = 22', content)

# Forcer listen_endpoints SSH sur le port 22 (uniquement dans la section [ssh])
content = re.sub(
    r'(?ms)(^\[ssh\])(.*?)(listen_endpoints\s*=\s*\S+)',
    lambda m: m.group(1) + m.group(2) + 'listen_endpoints = tcp:22:interface=0.0.0.0',
    content
)
# Si pas encore de listen_endpoints dans [ssh], en ajouter un après listen_port
if not re.search(r'(?ms)^\[ssh\].*?listen_endpoints', content):
    content = re.sub(
        r'(?m)(^\[ssh\][\s\S]*?listen_port\s*=.*?\n)',
        r'\1listen_endpoints = tcp:22:interface=0.0.0.0\n',
        content
    )

# Section [telnet] — activer + forcer port 23
content = re.sub(r'(?ms)(^\[telnet\].*?)(enabled\s*=\s*\w+)', r'\1enabled = true', content)
content = re.sub(
    r'(?ms)(^\[telnet\])(.*?)(listen_endpoints\s*=\s*\S+)',
    lambda m: m.group(1) + m.group(2) + 'listen_endpoints = tcp:23:interface=0.0.0.0',
    content
)
# Si pas encore de listen_endpoints dans [telnet], en ajouter un
if not re.search(r'(?ms)^\[telnet\].*?listen_endpoints', content):
    content = re.sub(
        r'(?ms)(^\[telnet\].*?enabled\s*=\s*true\n)',
        r'\1listen_endpoints = tcp:23:interface=0.0.0.0\n',
        content
    )

# Append [output_pglog] si absent
if '[output_pglog]' not in content:
    content += """
[output_pglog]
enabled = true
host = localhost
database = ${PG_DB}
username = ${PG_USER}
password = ${PG_PASS}
port = 5432
debug = false
"""

with open(cfg_path, 'w') as f:
    f.write(content)

print("cowrie.cfg mis à jour")
PYEOF

ok "cowrie.cfg configuré"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "6/12 — Plugin pglog (Cowrie → PostgreSQL)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

cat > "${COWRIE_HOME}/src/cowrie/output/pglog.py" << 'PYEOF'
"""
Custom Cowrie output plugin — writes directly into the unified 'events' table.
Section in cowrie.cfg: [output_pglog]
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
PYEOF

chown "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}/src/cowrie/output/pglog.py"
ok "Plugin pglog déployé"

# Créer les répertoires nécessaires au démarrage de Cowrie
sudo -u "${COWRIE_USER}" mkdir -p "${COWRIE_HOME}/var/log/cowrie"
sudo -u "${COWRIE_USER}" mkdir -p "${COWRIE_HOME}/var/run/cowrie"
ok "Répertoires var/ créés"

# Authbind : autoriser l'user cowrie à binder les ports 22 et 23 (< 1024)
# sans root (nécessaire pour systemd Type=simple avec User=cowrie)
touch /etc/authbind/byport/22 /etc/authbind/byport/23
chown "${COWRIE_USER}" /etc/authbind/byport/22 /etc/authbind/byport/23
chmod 500 /etc/authbind/byport/22 /etc/authbind/byport/23
ok "authbind configuré pour ports 22 et 23"

# Service systemd Cowrie
# On utilise twistd --nodaemon (Type=simple) pour éviter toute dépendance
# sur le script bin/cowrie du git clone (chemin variable selon la version).
# twistd est installé par requirements.txt (paquet Twisted).
cat > /etc/systemd/system/cowrie.service << SVCEOF
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target postgresql.service

[Service]
User=${COWRIE_USER}
WorkingDirectory=${COWRIE_HOME}
Environment=PYTHONPATH=${COWRIE_HOME}/src
Environment=HOME=/home/${COWRIE_USER}
ExecStart=/usr/bin/authbind --deep ${COWRIE_ENV}/bin/twistd --umask=0022 --nodaemon \
    --logfile=${COWRIE_HOME}/var/log/cowrie/cowrie.log \
    cowrie
ExecStop=/bin/kill -TERM \$MAINPID
Type=simple
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable cowrie
ok "Service cowrie.service créé"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "7/12 — OpenCanary (FTP / HTTP / MySQL / RDP / VNC)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Virtualenv
if [[ ! -x "${OPENCANARY_ENV}/bin/python3" ]]; then
    python3 -m venv "${OPENCANARY_ENV}"
    ok "Virtualenv opencanary-env créé"
fi
"${OPENCANARY_ENV}/bin/pip" install -q --upgrade pip
"${OPENCANARY_ENV}/bin/pip" install -q opencanary
ok "OpenCanary installé"

# Config
mkdir -p /etc/opencanaryd

# Nettoyer le hostname : garder uniquement les caractères acceptés par OpenCanary
# (lettres, chiffres, +, -, #, _) — remplace tout autre caractère par _
OC_HOSTNAME=$(hostname | tr -cs 'a-zA-Z0-9+#_-' '_' | sed 's/_$//')

cat > /etc/opencanaryd/opencanary.conf << JEOF
{
    "device.node_id": "opencanary-1",
    "device.name": "${OC_HOSTNAME}",
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
    "httpproxy.port": 8080,
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.5.43-0ubuntu0.14.04.1",
    "mysql.log_connection_made": false,
    "rdp.enabled": true,
    "rdp.port": 3389,
    "redis.enabled": false,
    "redis.port": 6379,
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
JEOF

# Créer le fichier log + droits
touch /var/log/opencanary.log
chmod 666 /var/log/opencanary.log

# Service systemd OpenCanary
# User=root nécessaire : OpenCanary binde des ports < 1024 (21, 80, 3306...)
# sans passer par sudo (qui nécessite un terminal interactif)
cat > /etc/systemd/system/opencanary.service << SVCEOF
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=${OPENCANARY_ENV}/bin/opencanaryd --dev
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable opencanary
ok "OpenCanary configuré (FTP:21 HTTP:80 MySQL:3306 RDP:3389 VNC:5900)"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "8/12 — honeypot-parser (OpenCanary → PostgreSQL, inotify)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Virtualenv dédié
if [[ ! -x "${PARSER_ENV}/bin/python3" ]]; then
    python3 -m venv "${PARSER_ENV}"
    ok "Virtualenv honeypot-parser-env créé"
fi
"${PARSER_ENV}/bin/pip" install -q --upgrade pip
"${PARSER_ENV}/bin/pip" install -q psycopg2-binary
ok "psycopg2-binary installé dans honeypot-parser-env"

# Script parser
cat > /opt/honeypot-to-postgres.py << 'PYEOF'
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
    "user": "honeypot", "password": "${PG_PASS}",
}
BATCH_SIZE     = 500
OPENCANARY_LOG = "/var/log/opencanary.log"
POSITION_FILE  = "/var/lib/honeypot-pos.json"

IN_MODIFY      = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
WATCH_MASK     = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
_EV            = struct.Struct("iIII")
_libc          = ctypes.CDLL("libc.so.6", use_errno=True)


def _inotify_init():
    fd = _libc.inotify_init1(0o4000)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1 failed")
    return fd


def _inotify_add_watch(ifd, path, mask=WATCH_MASK):
    wd = _libc.inotify_add_watch(ifd, path.encode(), mask)
    if wd < 0:
        raise OSError(ctypes.get_errno(), f"inotify_add_watch({path}) failed")
    return wd


def _drain(ifd):
    try:
        while True:
            os.read(ifd, 4096)
    except BlockingIOError:
        pass


_conn = None


def get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(**PG_CONFIG)
        _conn.autocommit = False
    return _conn


def parse_ts(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return ts_str, int(dt.timestamp() * 1000)
    except Exception:
        now = datetime.now(tz=timezone.utc)
        return now.isoformat(), int(now.timestamp() * 1000)


def insert_batch(batch):
    if not batch:
        return
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, """
                INSERT INTO events
                    (timestamp, ts, source, src_ip, dst_port,
                     event_type, username, password, message)
                VALUES %s ON CONFLICT DO NOTHING
            """, batch)
        conn.commit()
    except Exception as e:
        print(f"[ERROR] insert_batch: {e}")
        try:
            _conn.rollback()
        except Exception:
            pass


def check_rotation(filepath, last_pos):
    try:
        if last_pos > os.path.getsize(filepath):
            return 0
    except Exception:
        pass
    return last_pos


def parse_file(filepath, parser_func, last_pos):
    if not os.path.exists(filepath):
        return last_pos
    last_pos = check_rotation(filepath, last_pos)
    batch = []
    with open(filepath, "r", errors="replace") as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = parser_func(line)
                if event:
                    batch.append(event)
                if len(batch) >= BATCH_SIZE:
                    insert_batch(batch)
                    batch = []
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
    return (
        ts_str, ts_ms, "opencanary",
        e.get("src_host"), e.get("dst_port"),
        str(e.get("logtype")), username, password,
        json.dumps(logdata),
    )


def load_positions():
    try:
        with open(POSITION_FILE) as f:
            return json.load(f).get("opencanary", 0)
    except Exception:
        return 0


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
    save_positions(opencanary_pos)
    _drain(ifd)

    while True:
        ready = select.select([ifd], [], [], 5.0)[0]
        if ready:
            _drain(ifd)
        opencanary_pos = parse_file(OPENCANARY_LOG, parse_opencanary, opencanary_pos)
        save_positions(opencanary_pos)
PYEOF

# Substituer le mot de passe réel (le heredoc 'PYEOF' n'expand pas les variables)
sed -i "s/\${PG_PASS}/${PG_PASS}/g" /opt/honeypot-to-postgres.py

chmod +x /opt/honeypot-to-postgres.py

# Service systemd honeypot-parser
cat > /etc/systemd/system/honeypot-parser.service << SVCEOF
[Unit]
Description=Honeypot Log Parser
After=network.target postgresql.service

[Service]
Type=simple
ExecStart=${PARSER_ENV}/bin/python3 /opt/honeypot-to-postgres.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable honeypot-parser
ok "honeypot-parser configuré"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "9/12 — Grafana 12"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if ! command -v grafana-server &>/dev/null; then
    # Ajouter le dépôt officiel Grafana
    wget -q -O /tmp/grafana.gpg.key https://apt.grafana.com/gpg.key
    gpg --dearmor < /tmp/grafana.gpg.key > /usr/share/keyrings/grafana.gpg
    echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        > /etc/apt/sources.list.d/grafana.list
    apt-get update -qq
    apt-get install -y -qq grafana
    ok "Grafana installé"
else
    ok "Grafana déjà présent ($(grafana-server -v 2>/dev/null | head -1))"
fi

# Configurer Grafana (HTTPS avec certificat auto-signé)
GRAFANA_INI="/etc/grafana/grafana.ini"
[[ ! -f "${GRAFANA_INI}.orig" ]] && cp "${GRAFANA_INI}" "${GRAFANA_INI}.orig"

# Générer un certificat auto-signé (valide 10 ans)
GF_CERT_DIR="/etc/grafana/certs"
mkdir -p "${GF_CERT_DIR}"
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${GF_CERT_DIR}/grafana.key" \
    -out    "${GF_CERT_DIR}/grafana.crt" \
    -subj   "/CN=grafana-honeypot/O=HoneyPot/C=FR" 2>/dev/null
chown -R grafana:grafana "${GF_CERT_DIR}"
chmod 600 "${GF_CERT_DIR}/grafana.key"
ok "Certificat auto-signé Grafana généré (10 ans)"

# Activer HTTPS
sed -i 's/^;\?protocol = .*/protocol = https/'                         "${GRAFANA_INI}" || true
sed -i "s|^;\?http_port = .*|http_port = ${GRAFANA_PORT}|"             "${GRAFANA_INI}" || true
sed -i "s|^;\?cert_file = .*|cert_file = ${GF_CERT_DIR}/grafana.crt|" "${GRAFANA_INI}" || true
sed -i "s|^;\?cert_key = .*|cert_key  = ${GF_CERT_DIR}/grafana.key|"  "${GRAFANA_INI}" || true

systemctl enable grafana-server
systemctl start grafana-server

# Attendre que Grafana soit prêt
info "Attente démarrage Grafana..."
for i in $(seq 1 30); do
    if curl -sfk "https://localhost:${GRAFANA_PORT}/api/health" &>/dev/null; then
        ok "Grafana prêt"
        break
    fi
    sleep 2
    [[ $i -eq 30 ]] && warn "Grafana ne répond pas après 60s, continuer quand même"
done

# Changer le mot de passe admin
curl -sfk -X PUT \
    "https://admin:admin@localhost:${GRAFANA_PORT}/api/user/password" \
    -H "Content-Type: application/json" \
    -d "{\"oldPassword\":\"admin\",\"newPassword\":\"${GRAFANA_ADMIN_PASS}\"}" \
    &>/dev/null && ok "Mot de passe Grafana admin changé" || \
    warn "Mot de passe Grafana déjà changé ou autre erreur (ignoré)"

# Créer la datasource PostgreSQL
DS_RESPONSE=$(curl -sfk \
    -u "admin:${GRAFANA_ADMIN_PASS}" \
    -X POST "https://localhost:${GRAFANA_PORT}/api/datasources" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"PostgreSQL\",
        \"type\": \"grafana-postgresql-datasource\",
        \"url\": \"localhost:5432\",
        \"database\": \"${PG_DB}\",
        \"user\": \"${PG_USER}\",
        \"secureJsonData\": {\"password\": \"${PG_PASS}\"},
        \"jsonData\": {\"sslmode\": \"disable\", \"postgresVersion\": 1600},
        \"isDefault\": true,
        \"access\": \"proxy\"
    }" 2>&1 || true)

if echo "${DS_RESPONSE}" | grep -q '"id"'; then
    ok "Datasource PostgreSQL créée dans Grafana"
elif echo "${DS_RESPONSE}" | grep -q 'already exists'; then
    ok "Datasource PostgreSQL déjà présente"
else
    warn "Datasource : réponse inattendue (à vérifier manuellement) : ${DS_RESPONSE}"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "10/12 — Démarrage de tous les services"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

systemctl start cowrie
sleep 3
systemctl start opencanary
sleep 2
systemctl start honeypot-parser

ok "Services démarrés"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "11/12 — Déploiement dashboard Grafana (20 panels)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

info "Génération du script de déploiement dashboard..."
cat > /tmp/honeypot_deploy.py << 'PYEOF'
#!/usr/bin/env python3
import getpass, json, os, ssl, base64, urllib.request, urllib.error
import psycopg2, psycopg2.extras  # type: ignore

GF_USER    = "admin"
PG_DS_TYPE = "grafana-postgresql-datasource"
DASH_UID   = "honeypot-v4"

GF_PASS = os.environ.get("GF_PASS") or getpass.getpass("Mot de passe Grafana admin : ")
PG_PASS = os.environ.get("PG_PASS") or getpass.getpass("Mot de passe PostgreSQL (honeypot) : ")

PG = dict(host="localhost", dbname="honeypot", user="honeypot", password=PG_PASS)

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def _detect_grafana_url():
    for proto in ("http", "https"):
        url = f"{proto}://localhost:3000/api/health"
        try:
            kw = {"context": ctx} if proto == "https" else {}
            urllib.request.urlopen(url, timeout=3, **kw)
            print(f"[GF] Grafana détecté en {proto}")
            return f"{proto}://localhost:3000"
        except Exception:
            pass
    raise RuntimeError("Grafana inaccessible sur http ni https :3000")

GRAFANA = _detect_grafana_url()

PORT_VAR = {
    "type": "custom", "name": "port", "label": "Port", "hide": 0,
    "current": {"selected": True, "text": "All", "value": "0"},
    "includeAll": False, "multi": False, "skipUrlSync": False,
    "query": "All : 0, SSH (22) : 22, Telnet (23) : 23, FTP (21) : 21, HTTP (80) : 80, MySQL (3306) : 3306, RDP (3389) : 3389, VNC (5900) : 5900",
    "options": [
        {"selected": True,  "text": "All",           "value": "0"},
        {"selected": False, "text": "SSH (22)",      "value": "22"},
        {"selected": False, "text": "Telnet (23)",   "value": "23"},
        {"selected": False, "text": "FTP (21)",      "value": "21"},
        {"selected": False, "text": "HTTP (80)",     "value": "80"},
        {"selected": False, "text": "MySQL (3306)",  "value": "3306"},
        {"selected": False, "text": "RDP (3389)",    "value": "3389"},
        {"selected": False, "text": "VNC (5900)",    "value": "5900"},
    ],
}

creds = base64.b64encode(f"{GF_USER}:{GF_PASS}".encode()).decode()
headers = {"Authorization": "Basic " + creds, "Content-Type": "application/json"}

def _ctx():
    return {"context": ctx} if GRAFANA.startswith("https") else {}

def gf_get(path):
    r = urllib.request.urlopen(urllib.request.Request(GRAFANA+path, headers=headers), **_ctx())
    return json.loads(r.read())

def gf_post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(GRAFANA+path, data=data, headers=headers, method="POST")
    return json.loads(urllib.request.urlopen(req, **_ctx()).read())

def _get_pg_ds_uid():
    for ds in gf_get("/api/datasources"):
        if ds.get("type") == PG_DS_TYPE:
            uid = ds["uid"]
            print(f"[GF] Datasource PostgreSQL trouvée : uid={uid} name={ds.get('name')}")
            return uid, ds["type"]
    raise RuntimeError(f"Aucune datasource de type '{PG_DS_TYPE}' trouvée dans Grafana.")

PG_DS_UID, _ = _get_pg_ds_uid()
DS = {"type": PG_DS_TYPE, "uid": PG_DS_UID}

def panel(id_, title, type_, gridPos, targets, options=None, fieldConfig=None, **kw):
    p = {"id": id_, "title": title, "type": type_, "gridPos": gridPos,
         "datasource": DS, "targets": targets}
    if options:     p["options"]     = options
    if fieldConfig: p["fieldConfig"] = fieldConfig
    p.update(kw)
    return p

def tbl(refId, sql):
    return {"refId": refId, "datasource": DS, "rawSql": sql, "format": "table"}

def ts(refId, sql):
    return {"refId": refId, "datasource": DS, "rawSql": sql, "format": "time_series"}

def stat_fc(steps, unit="none"):
    return {"defaults": {"color": {"mode": "thresholds"},
                         "thresholds": {"mode": "absolute", "steps": steps},
                         "unit": unit, "mappings": []}, "overrides": []}

def stat_opts():
    return {"colorMode": "background", "graphMode": "none",
            "justifyMode": "center", "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "/^(value|n)$/", "values": False},
            "textMode": "auto"}

_IVAL  = "GREATEST($__interval_ms::bigint, 10000)"
BUCKET = f"to_timestamp(floor(ts/{_IVAL}::float)*{_IVAL}/1000.0)"
GRP5   = f"floor(ts/{_IVAL}::float)"
TRANGE = "ts BETWEEN $__from AND $__to"
PORT_F = "(NULLIF('$port','0') IS NULL OR dst_port = NULLIF('$port','0')::integer)"

# ── VACUUM ANALYZE ────────────────────────────────────────────────────────────
print("="*60)
print("[PG] VACUUM ANALYZE events …")
conn = psycopg2.connect(**PG)
conn.autocommit = True
cur = conn.cursor()
cur.execute("VACUUM ANALYZE events")
cur.execute("SELECT COUNT(*) FROM events;")
count = cur.fetchone()[0]
print(f"[PG] Table events : {count} ligne(s)")
cur.close(); conn.close()
print("[PG] Done\n")

# ── Construction des panels ───────────────────────────────────────────────────
print("[GF] Construction du dashboard …")

stat_connexions = panel(1, "🔌 Total Connexions", "stat",
    {"h":4,"w":4,"x":0,"y":0},
    [tbl("A", f"SELECT COUNT(*) AS value FROM events WHERE {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"blue","value":0},{"color":"orange","value":100},{"color":"red","value":1000}]))

stat_ips = panel(2, "🌍 IPs Uniques", "stat",
    {"h":4,"w":4,"x":4,"y":0},
    [tbl("A", f"SELECT COUNT(DISTINCT src_ip) AS value FROM events WHERE src_ip != '' AND {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"green","value":0},{"color":"orange","value":20},{"color":"red","value":100}]))

stat_logins_ok = panel(3, "⚠️ Logins Réussis ALARME", "stat",
    {"h":4,"w":4,"x":8,"y":0},
    [tbl("A", f"SELECT COUNT(*) AS value FROM events WHERE event_type='cowrie.login.success' AND {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"green","value":0},{"color":"red","value":1}]))

stat_cmds = panel(4, "💻 Commandes Exécutées", "stat",
    {"h":4,"w":4,"x":12,"y":0},
    [tbl("A", f"SELECT COUNT(*) AS value FROM events WHERE event_type='cowrie.command.input' AND {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"blue","value":0},{"color":"orange","value":100},{"color":"red","value":1000}]))

stat_uploads = panel(5, "🗂️ Fichiers Uploadés (Malware)", "stat",
    {"h":4,"w":4,"x":16,"y":0},
    [tbl("A", f"SELECT COUNT(*) AS value FROM events WHERE event_type='cowrie.session.file_upload' AND {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"green","value":0},{"color":"red","value":1}]))

stat_logins_fail = panel(6, "🚫 Logins Échoués", "stat",
    {"h":4,"w":4,"x":20,"y":0},
    [tbl("A", f"SELECT COUNT(*) AS value FROM events WHERE event_type IN ('cowrie.login.failed','1001') AND {TRANGE} AND {PORT_F}")],
    stat_opts(), stat_fc([{"color":"blue","value":0},{"color":"orange","value":100},{"color":"red","value":500}]))

ts_global_sql = f"""
SELECT
  {BUCKET} AS time,
  SUM(CASE WHEN event_type='cowrie.session.connect'      THEN 1 ELSE 0 END) AS "SSH/Telnet",
  SUM(CASE WHEN event_type='cowrie.login.success'        THEN 1 ELSE 0 END) AS "Logins Réussis",
  SUM(CASE WHEN event_type='cowrie.command.input'        THEN 1 ELSE 0 END) AS "Commandes",
  SUM(CASE WHEN event_type='cowrie.session.file_upload'  THEN 1 ELSE 0 END) AS "Upload Malware",
  SUM(CASE WHEN event_type='2000'                         THEN 1 ELSE 0 END) AS "FTP",
  SUM(CASE WHEN event_type='3000' OR event_type='3001'    THEN 1 ELSE 0 END) AS "HTTP",
  SUM(CASE WHEN event_type='8001'                         THEN 1 ELSE 0 END) AS "MySQL",
  SUM(CASE WHEN event_type='14001'                        THEN 1 ELSE 0 END) AS "RDP",
  SUM(CASE WHEN event_type='12001'                        THEN 1 ELSE 0 END) AS "VNC"
FROM events WHERE {TRANGE} AND {PORT_F}
GROUP BY {GRP5} ORDER BY 1 ASC
"""
ts_activite = panel(7, "📈 Activité dans le Temps — Toutes Sources", "timeseries",
    {"h":9,"w":24,"x":0,"y":4},
    [ts("A", ts_global_sql)],
    {"legend":{"calcs":["sum","max"],"displayMode":"table","placement":"right","showLegend":True},
     "tooltip":{"mode":"multi","sort":"desc"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":12,"lineWidth":2,"spanNulls":True}},"overrides":[]})

top_ips = panel(8, "🏆 Top 10 IPs Attaquantes", "barchart",
    {"h":8,"w":14,"x":0,"y":13},
    [tbl("A", f"SELECT src_ip, COUNT(*) AS attaques FROM events WHERE src_ip != '' AND {TRANGE} AND {PORT_F} GROUP BY src_ip ORDER BY attaques DESC LIMIT 10")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},
     "orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

proto_sql = f"""
SELECT
  CASE
    WHEN source='cowrie'      AND dst_port=22  THEN '🔑 SSH (22)'
    WHEN source='cowrie'      AND dst_port=23  THEN '📟 Telnet (23)'
    WHEN event_type='2000'                     THEN '📁 FTP (21)'
    WHEN event_type='3000'  OR event_type='3001' THEN '🌐 HTTP (80)'
    WHEN event_type='8001'                     THEN '🗄️ MySQL (3306)'
    WHEN event_type='14001'                    THEN '🖥️ RDP (3389)'
    WHEN event_type='12001'                    THEN '🖱️ VNC (5900)'
    WHEN event_type='1001'                     THEN '🔐 SSH (OpenCanary)'
    WHEN event_type='9001'                     THEN '📟 Telnet (OpenCanary)'
  END AS protocole,
  COUNT(*) AS connexions
FROM events
WHERE {TRANGE} AND {PORT_F}
  AND ((source='cowrie' AND dst_port IN (22,23))
       OR (source='opencanary' AND event_type IN ('1001','2000','3000','3001','8001','9001','12001','14001')))
GROUP BY 1 HAVING COUNT(*) > 0 ORDER BY 2 DESC
"""
donut_proto = panel(9, "🔀 Répartition par Protocole", "piechart",
    {"h":8,"w":10,"x":14,"y":13},
    [tbl("A", proto_sql)],
    {"displayLabels":["name","percent"],"legend":{"calcs":["sum"],"displayMode":"table","placement":"right","showLegend":True},
     "pieType":"donut","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":True},
     "tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"hideFrom":{"legend":False,"tooltip":False,"viz":False}},"mappings":[]},"overrides":[]})

logins_ip = panel(10, "🔓 Logins Réussis par IP", "barchart",
    {"h":8,"w":12,"x":0,"y":21},
    [tbl("A", f"SELECT src_ip, COUNT(*) AS logins FROM events WHERE event_type='cowrie.login.success' AND {TRANGE} AND {PORT_F} GROUP BY src_ip ORDER BY logins DESC LIMIT 10")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},"orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

top_cmds = panel(11, "💻 Top Commandes Exécutées", "barchart",
    {"h":8,"w":12,"x":12,"y":21},
    [tbl("A", f"SELECT message, COUNT(*) AS fois FROM events WHERE event_type='cowrie.command.input' AND message != '' AND {TRANGE} AND {PORT_F} GROUP BY message ORDER BY fois DESC LIMIT 15")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},"orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

top_users = panel(12, "👤 Top Usernames Essayés", "barchart",
    {"h":8,"w":12,"x":0,"y":29},
    [tbl("A", f"SELECT username, COUNT(*) AS total FROM events WHERE username IS NOT NULL AND username != '' AND {TRANGE} AND {PORT_F} GROUP BY username ORDER BY total DESC LIMIT 15")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},"orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

top_pass = panel(13, "🔑 Top Passwords Essayés", "barchart",
    {"h":8,"w":12,"x":12,"y":29},
    [tbl("A", f"SELECT password, COUNT(*) AS total FROM events WHERE password IS NOT NULL AND password != '' AND {TRANGE} AND {PORT_F} GROUP BY password ORDER BY total DESC LIMIT 15")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},"orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

journal_fc = {
    "defaults": {"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"minWidth":80},
                 "thresholds":{"mode":"absolute","steps":[{"color":"green","value":0}]}},
    "overrides": [
        {"matcher":{"id":"byName","options":"timestamp"}, "properties":[{"id":"displayName","value":"Heure"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"src_ip"},    "properties":[{"id":"displayName","value":"IP Attaquant"},{"id":"custom.width","value":135}]},
        {"matcher":{"id":"byName","options":"dst_port"},  "properties":[{"id":"displayName","value":"Port"},{"id":"custom.width","value":65}]},
        {"matcher":{"id":"byName","options":"source"},    "properties":[{"id":"displayName","value":"Source"},{"id":"custom.width","value":90}]},
        {"matcher":{"id":"byName","options":"type_label"},"properties":[{"id":"displayName","value":"Événement"},{"id":"custom.width","value":180}]},
        {"matcher":{"id":"byName","options":"username"},  "properties":[{"id":"displayName","value":"Login"},{"id":"custom.width","value":110}]},
        {"matcher":{"id":"byName","options":"password"},  "properties":[{"id":"displayName","value":"Password"},{"id":"custom.width","value":120}]},
        {"matcher":{"id":"byName","options":"message"},   "properties":[{"id":"displayName","value":"Détail"}]},
    ]
}
journal_sql = f"""
SELECT timestamp, source, src_ip, dst_port,
  CASE event_type
    WHEN 'cowrie.session.connect'       THEN '🔌 Connexion'
    WHEN 'cowrie.login.failed'          THEN '❌ Login échoué'
    WHEN 'cowrie.login.success'         THEN '🚨 LOGIN RÉUSSI'
    WHEN 'cowrie.command.input'         THEN '💻 Commande'
    WHEN 'cowrie.session.file_upload'   THEN '📤 Upload malware'
    WHEN 'cowrie.session.file_download' THEN '📥 Download'
    WHEN '1001'  THEN '🔐 SSH (OpenCanary)'
    WHEN '2000'  THEN '📁 FTP login'
    WHEN '3000'  THEN '🌐 HTTP request'
    WHEN '3001'  THEN '🌐 HTTP login'
    WHEN '12001' THEN '🖱️ VNC login'
    WHEN '8001'  THEN '🗄️ MySQL login'
    WHEN '9001'  THEN '📟 Telnet login'
    WHEN '14001' THEN '🖥️ RDP login'
    ELSE event_type
  END AS type_label,
  username, password, message
FROM events
WHERE src_ip IS NOT NULL AND src_ip != '' AND {TRANGE} AND {PORT_F}
ORDER BY ts DESC LIMIT 300
"""
journal = panel(14, "📋 Journal des Attaques en Temps Réel", "table",
    {"h":12,"w":24,"x":0,"y":37},
    [tbl("A", journal_sql)],
    {"cellHeight":"sm","footer":{"show":False},"showHeader":True,"sortBy":[{"desc":True,"displayName":"Heure"}]},
    journal_fc)

cmds_table = panel(15, "💻 Commandes Exécutées par les Attaquants", "table",
    {"h":10,"w":12,"x":0,"y":49},
    [tbl("A", f"SELECT timestamp, src_ip, message FROM events WHERE event_type='cowrie.command.input' AND {TRANGE} AND {PORT_F} ORDER BY ts DESC LIMIT 100")],
    {"cellHeight":"sm","footer":{"show":False},"showHeader":True},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"align":"auto","cellOptions":{"type":"auto"}}},"overrides":[
        {"matcher":{"id":"byName","options":"timestamp"},"properties":[{"id":"displayName","value":"Heure"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"src_ip"},"properties":[{"id":"displayName","value":"IP"},{"id":"custom.width","value":130}]},
        {"matcher":{"id":"byName","options":"message"},"properties":[{"id":"displayName","value":"Commande"}]}]})

uploads_table = panel(16, "🗂️ Fichiers Uploadés (Malware/Backdoors)", "table",
    {"h":10,"w":12,"x":12,"y":49},
    [tbl("A", f"SELECT timestamp, src_ip, message FROM events WHERE event_type='cowrie.session.file_upload' AND {TRANGE} AND {PORT_F} ORDER BY ts DESC LIMIT 100")],
    {"cellHeight":"sm","footer":{"show":False},"showHeader":True},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"align":"auto","cellOptions":{"type":"auto"}}},"overrides":[
        {"matcher":{"id":"byName","options":"timestamp"},"properties":[{"id":"displayName","value":"Heure"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"src_ip"},"properties":[{"id":"displayName","value":"IP"},{"id":"custom.width","value":130}]},
        {"matcher":{"id":"byName","options":"message"},"properties":[{"id":"displayName","value":"Fichier / Détails"}]}]})

row_ports = {"collapsed":False,"gridPos":{"h":1,"w":24,"x":0,"y":59},"id":20,"title":"🔍 Surveillance des Ports Honeypot","type":"row"}

port_label = """CASE dst_port
  WHEN 22   THEN '🔑 SSH (22)'
  WHEN 23   THEN '📟 Telnet (23)'
  WHEN 21   THEN '📁 FTP (21)'
  WHEN 80   THEN '🌐 HTTP (80)'
  WHEN 3306 THEN '🗄️ MySQL (3306)'
  WHEN 3389 THEN '🖥️ RDP (3389)'
  WHEN 5900 THEN '🖱️ VNC (5900)'
  ELSE 'Autre (' || dst_port::text || ')' END"""

bar_ports = panel(17, "🛡️ Connexions par Port Honeypot", "barchart",
    {"h":8,"w":12,"x":0,"y":60},
    [tbl("A", f"SELECT {port_label} AS port_service, COUNT(*) AS connexions FROM events WHERE dst_port > 0 AND {TRANGE} AND {PORT_F} GROUP BY dst_port ORDER BY connexions DESC")],
    {"barRadius":0.1,"barWidth":0.6,"legend":{"displayMode":"list","placement":"bottom","showLegend":True},"orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

ts_port_sql = f"""
SELECT {BUCKET} AS time,
  SUM(CASE WHEN dst_port=22   THEN 1 ELSE 0 END) AS "SSH 22",
  SUM(CASE WHEN dst_port=23   THEN 1 ELSE 0 END) AS "Telnet 23",
  SUM(CASE WHEN dst_port=21   THEN 1 ELSE 0 END) AS "FTP 21",
  SUM(CASE WHEN dst_port=80   THEN 1 ELSE 0 END) AS "HTTP 80",
  SUM(CASE WHEN dst_port=3306 THEN 1 ELSE 0 END) AS "MySQL 3306",
  SUM(CASE WHEN dst_port=3389 THEN 1 ELSE 0 END) AS "RDP 3389",
  SUM(CASE WHEN dst_port=5900 THEN 1 ELSE 0 END) AS "VNC 5900"
FROM events WHERE dst_port > 0 AND {TRANGE} AND {PORT_F}
GROUP BY {GRP5} ORDER BY 1 ASC
"""
ts_ports = panel(18, "📡 Activité par Port dans le Temps", "timeseries",
    {"h":8,"w":12,"x":12,"y":60},
    [ts("A", ts_port_sql)],
    {"legend":{"calcs":["sum"],"displayMode":"table","placement":"right","showLegend":True},"tooltip":{"mode":"multi","sort":"desc"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":12,"lineWidth":2,"spanNulls":True}},"overrides":[]})

recap_sql = f"""
SELECT {port_label} AS port_service,
  COUNT(*) AS total, COUNT(DISTINCT src_ip) AS ips_uniques,
  MIN(timestamp) AS premiere, MAX(timestamp) AS derniere
FROM events WHERE dst_port > 0 AND {TRANGE} AND {PORT_F}
GROUP BY dst_port ORDER BY total DESC
"""
recap_fc = {
    "defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"}},"thresholds":{"mode":"absolute","steps":[{"color":"green","value":0}]}},
    "overrides":[
        {"matcher":{"id":"byName","options":"port_service"},"properties":[{"id":"displayName","value":"Port / Service"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"premiere"},    "properties":[{"id":"displayName","value":"1ère Attaque"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"derniere"},    "properties":[{"id":"displayName","value":"Dernière Attaque"},{"id":"custom.width","value":190}]},
        {"matcher":{"id":"byName","options":"ips_uniques"}, "properties":[{"id":"displayName","value":"IPs Uniques"},{"id":"custom.width","value":90}]},
        {"matcher":{"id":"byName","options":"total"},       "properties":[{"id":"displayName","value":"Total"}]},
    ]
}
recap_ports = panel(19, "📊 Récap — Tous les Ports Honeypot", "table",
    {"h":7,"w":24,"x":0,"y":68},
    [tbl("A", recap_sql)],
    {"cellHeight":"sm","footer":{"show":False},"showHeader":True,"sortBy":[{"desc":True,"displayName":"Total"}]},
    recap_fc)

dashboard = {
    "uid":           DASH_UID,
    "title":         "🍯 Honeypot Dashboard",
    "description":   "Honeypot Dashboard — Cowrie + OpenCanary → PostgreSQL",
    "tags":          ["honeypot", "security", "cowrie", "opencanary"],
    "editable":      True,
    "graphTooltip":  1,
    "refresh":       "5s",
    "schemaVersion": 42,
    "time":          {"from": "now-24h", "to": "now"},
    "timepicker":    {},
    "timezone":      "browser",
    "annotations":   {"list": []},
    "links":         [],
    "panels": [
        stat_connexions, stat_ips, stat_logins_ok, stat_cmds, stat_uploads, stat_logins_fail,
        ts_activite, top_ips, donut_proto, logins_ip, top_cmds, top_users, top_pass,
        journal, cmds_table, uploads_table, row_ports, bar_ports, ts_ports, recap_ports,
    ],
    "templating": {"list": [PORT_VAR]},
    "version": 1,
}

print("[GF] Envoi du dashboard vers Grafana …")
result = gf_post("/api/dashboards/db", {"dashboard": dashboard, "overwrite": True, "folderId": 0})
print(f"[GF] status={result.get('status')}  url={result.get('url')}")
print("\n✅ Dashboard déployé avec succès.")
PYEOF

info "Déploiement du dashboard dans Grafana..."
if GF_PASS="${GRAFANA_ADMIN_PASS}" PG_PASS="${PG_PASS}" \
    "${PARSER_ENV}/bin/python3" /tmp/honeypot_deploy.py; then
    ok "Dashboard '🍯 Honeypot Dashboard' déployé ✓ (20 panels)"
else
    warn "Erreur lors du déploiement dashboard — relancer manuellement :"
    warn "  GF_PASS=xxx PG_PASS=yyy ${PARSER_ENV}/bin/python3 /tmp/honeypot_deploy.py"
fi
rm -f /tmp/honeypot_deploy.py

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
step "12/12 — Vérification"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
info "Statut des services :"
for SVC in postgresql cowrie opencanary honeypot-parser grafana-server; do
    STATUS=$(systemctl is-active "${SVC}" 2>/dev/null || echo "inconnu")
    if [[ "$STATUS" == "active" ]]; then
        echo -e "  ${GREEN}✔${NC} ${SVC}"
    else
        echo -e "  ${RED}✘${NC} ${SVC} (${STATUS})"
    fi
done

echo ""
info "Ports en écoute :"
ss -tlnp 2>/dev/null | grep -E ':22 |:23 |:21 |:80 |:3306 |:3389 |:5432 |:5900 |:3000 ' || true

echo ""
info "Événements en base (attendu 0 sur install fraîche) :"
sudo -u postgres psql -d "${PG_DB}" -c "SELECT COUNT(*) AS total_events FROM events;" 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║           INSTALLATION TERMINÉE ✔               ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}SSH admin     :${NC}  ssh -p ${SSH_ADMIN_PORT} ubuntu@${IP}"
echo -e "  ${CYAN}Grafana       :${NC}  https://${IP}:${GRAFANA_PORT}  (cert auto-signé — ignorer l'alerte navigateur)"
echo -e "  ${CYAN}  login       :${NC}  admin / ${GRAFANA_ADMIN_PASS}"
echo -e "  ${CYAN}PostgreSQL    :${NC}  localhost:5432  db=${PG_DB}  user=${PG_USER}"
echo ""
echo -e "  Dashboard déployé : ${CYAN}https://${IP}:${GRAFANA_PORT}${NC} → '🍯 Honeypot Dashboard'"
echo ""
