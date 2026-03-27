#!/usr/bin/env python3
"""
Honeypot dashboard deployer (standalone)
  1. PostgreSQL: VACUUM ANALYZE
  2. Grafana: auto-découverte datasource UID + déploiement dashboard complet
Utilisé uniquement pour re-déployer manuellement — install.sh le lance automatiquement.

Les mots de passe sont lus depuis les variables d'environnement ou demandés
interactivement si elles ne sont pas définies :
  GF_PASS  — mot de passe Grafana admin
  PG_PASS  — mot de passe PostgreSQL utilisateur honeypot
"""
import getpass, json, os, ssl, base64, urllib.request, urllib.error
import psycopg2, psycopg2.extras  # type: ignore

# ── Config ────────────────────────────────────────────────────────────────────
GF_USER    = "admin"
PG_DS_TYPE = "grafana-postgresql-datasource"
DASH_UID   = "honeypot-v4"

# Lecture depuis l'environnement, sinon demande interactive
GF_PASS = os.environ.get("GF_PASS") or getpass.getpass("Mot de passe Grafana admin : ")
PG_PASS = os.environ.get("PG_PASS") or getpass.getpass("Mot de passe PostgreSQL (honeypot) : ")

PG = dict(host="localhost", dbname="honeypot", user="honeypot", password=PG_PASS)

# ── Auto-détection protocole Grafana (http ou https) ─────────────────────────
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

# ── Port filter variable definition ──────────────────────────────────────────
PORT_VAR = {
    "type": "custom",
    "name": "port",
    "label": "Port",
    "hide": 0,
    "current": {"selected": True, "text": "All", "value": "0"},
    "includeAll": False,
    "multi": False,
    "skipUrlSync": False,
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

# ── Grafana helpers ───────────────────────────────────────────────────────────
creds = base64.b64encode(f"{GF_USER}:{GF_PASS}".encode()).decode()
headers = {"Authorization": "Basic " + creds, "Content-Type": "application/json"}

def _ctx():
    if GRAFANA.startswith("https"):
        return {"context": ctx}
    return {}

def gf_get(path):
    r = urllib.request.urlopen(urllib.request.Request(GRAFANA+path, headers=headers), **_ctx())
    return json.loads(r.read())

def gf_post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(GRAFANA+path, data=data, headers=headers, method="POST")
    return json.loads(urllib.request.urlopen(req, **_ctx()).read())

# ── Auto-découverte UID de la datasource PostgreSQL ───────────────────────────
def _get_pg_ds_uid():
    datasources = gf_get("/api/datasources")
    for ds in datasources:
        if ds.get("type") == PG_DS_TYPE:
            uid = ds["uid"]
            print(f"[GF] Datasource PostgreSQL trouvée : uid={uid} name={ds.get('name')}")
            return uid, ds["type"]
    raise RuntimeError(
        f"Aucune datasource de type '{PG_DS_TYPE}' trouvée dans Grafana.\n"
        "Créez-la d'abord : Settings → Data Sources → Add → PostgreSQL"
    )

PG_DS_UID, _ = _get_pg_ds_uid()
DS = {"type": PG_DS_TYPE, "uid": PG_DS_UID}

def panel(id_, title, type_, gridPos, targets, options=None, fieldConfig=None, **kw):
    p = {"id": id_, "title": title, "type": type_, "gridPos": gridPos,
         "datasource": DS, "targets": targets}
    if options:    p["options"]     = options
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

# 5-min bucket helper (bigint ms → timestamptz)
# Dynamic interval: adapts to the selected time range in Grafana
# GREATEST ensures minimum 10-second buckets to avoid division by zero
_IVAL  = "GREATEST($__interval_ms::bigint, 10000)"
BUCKET = f"to_timestamp(floor(ts/{_IVAL}::float)*{_IVAL}/1000.0)"
GRP5   = f"floor(ts/{_IVAL}::float)"
TRANGE = "ts BETWEEN $__from AND $__to"
# Port filter: NULLIF trick → when $port='0' (All) the condition is always TRUE
PORT_F = "(NULLIF('$port','0') IS NULL OR dst_port = NULLIF('$port','0')::integer)"

# OpenCanary type label (CASE)
OC_LABEL = """CASE event_type
  WHEN '1001'  THEN 'SSH'
  WHEN '2000'  THEN 'Telnet'
  WHEN '3000'  THEN 'FTP'
  WHEN '5001'  THEN 'HTTP Login'
  WHEN '8001'  THEN 'MySQL'
  WHEN '12001' THEN 'VNC'
  WHEN '14001' THEN 'RDP'
  ELSE event_type END"""

# ── 1. PostgreSQL — VACUUM ANALYZE ───────────────────────────────────────────
# Les index sont créés par setup.sh. On fait juste un VACUUM ANALYZE
# pour s'assurer que le planner a des stats à jour après le premier remplissage.
print("═"*60)
print("[PG] VACUUM ANALYZE events …")
conn = psycopg2.connect(**PG)
conn.autocommit = True
cur = conn.cursor()
cur.execute("VACUUM ANALYZE events")

cur.execute("SELECT indexname, pg_size_pretty(pg_relation_size(indexname::regclass)) FROM pg_indexes WHERE tablename='events' ORDER BY 1;")
print("[PG] Index en place :")
for row in cur.fetchall(): print(f"    {row[0]:50s} {row[1]}")

cur.execute("SELECT pg_size_pretty(pg_total_relation_size('events')), COUNT(*) FROM events;")
size, count = cur.fetchone()
print(f"[PG] Table events : {count} lignes / {size}")
cur.close(); conn.close()
print("[PG] Done ✓\n")

# ── 2. Construction du dashboard ──────────────────────────────────────────────
print("[GF] Construction du dashboard …")

# ── Stats row ─────────────────────────────────────────────────────────────────
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

# ── Timeseries global (FIX GROUP BY) ─────────────────────────────────────────
ts_global_sql = f"""
SELECT
  {BUCKET} AS time,
  SUM(CASE WHEN event_type='cowrie.session.connect'      THEN 1 ELSE 0 END) AS "SSH/Telnet",
  SUM(CASE WHEN event_type='cowrie.login.success'        THEN 1 ELSE 0 END) AS "Logins Réussis",
  SUM(CASE WHEN event_type='cowrie.command.input'        THEN 1 ELSE 0 END) AS "Commandes",
  SUM(CASE WHEN event_type='cowrie.session.file_upload'  THEN 1 ELSE 0 END) AS "Upload Malware",
  SUM(CASE WHEN event_type='8001'                        THEN 1 ELSE 0 END) AS "MySQL",
  SUM(CASE WHEN event_type='14001'                       THEN 1 ELSE 0 END) AS "RDP",
  SUM(CASE WHEN event_type='12001'                       THEN 1 ELSE 0 END) AS "VNC"
FROM events
WHERE {TRANGE} AND {PORT_F}
GROUP BY {GRP5}
ORDER BY 1 ASC
"""
ts_activite = panel(7, "📈 Activité dans le Temps — Toutes Sources", "timeseries",
    {"h":9,"w":24,"x":0,"y":4},
    [ts("A", ts_global_sql)],
    {"legend":{"calcs":["sum","max"],"displayMode":"table","placement":"right","showLegend":True},
     "tooltip":{"mode":"multi","sort":"desc"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":12,"lineWidth":2,"spanNulls":True}},"overrides":[]})

# ── Top IPs + protocoles ──────────────────────────────────────────────────────
top_ips = panel(8, "🏆 Top 10 IPs Attaquantes", "barchart",
    {"h":8,"w":14,"x":0,"y":13},
    [tbl("A", f"SELECT src_ip, COUNT(*) AS attaques FROM events WHERE src_ip != '' AND {TRANGE} AND {PORT_F} GROUP BY src_ip ORDER BY attaques DESC LIMIT 10")],
    {"barRadius":0.1,"barWidth":0.7,"legend":{"displayMode":"list","placement":"bottom","showLegend":False},
     "orientation":"horizontal","showValue":"always","tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":80,"lineWidth":1}},"overrides":[]})

proto_sql = f"""
SELECT
  CASE
    WHEN source='cowrie'      AND dst_port=22  THEN '🔑 SSH (Cowrie)'
    WHEN source='cowrie'      AND dst_port=23  THEN '📟 Telnet (Cowrie)'
    WHEN event_type='8001'                     THEN '🗄️ MySQL 3306'
    WHEN event_type='14001'                    THEN '🖥️ RDP 3389'
    WHEN event_type='12001'                    THEN '🖱️ VNC 5900'
    WHEN event_type='3000'                     THEN '📁 FTP 21'
    WHEN event_type='1001'                     THEN '🔐 SSH (OpenCanary)'
    WHEN event_type='2000'                     THEN '📟 Telnet (OpenCanary)'
  END AS protocole,
  COUNT(*) AS connexions
FROM events
WHERE {TRANGE}
  AND {PORT_F}
  AND (
    (source='cowrie'      AND dst_port IN (22, 23))
    OR (source='opencanary' AND event_type IN ('1001','2000','3000','8001','12001','14001'))
  )
GROUP BY 1
HAVING COUNT(*) > 0
ORDER BY 2 DESC
"""
donut_proto = panel(9, "🔀 Répartition par Protocole", "piechart",
    {"h":8,"w":10,"x":14,"y":13},
    [tbl("A", proto_sql)],
    {"displayLabels":["name","percent"],"legend":{"calcs":["sum"],"displayMode":"table","placement":"right","showLegend":True},
     "pieType":"donut","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":True},
     "tooltip":{"mode":"single","sort":"none"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"hideFrom":{"legend":False,"tooltip":False,"viz":False}},"mappings":[]},"overrides":[]})

# ── Logins & commandes ────────────────────────────────────────────────────────
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

# ── Credentials ───────────────────────────────────────────────────────────────
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

# ── Journal temps réel ────────────────────────────────────────────────────────
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
SELECT
  timestamp,
  source,
  src_ip,
  dst_port,
  CASE event_type
    WHEN 'cowrie.session.connect'       THEN '🔌 Connexion'
    WHEN 'cowrie.login.failed'          THEN '❌ Login échoué'
    WHEN 'cowrie.login.success'         THEN '🚨 LOGIN RÉUSSI'
    WHEN 'cowrie.command.input'         THEN '💻 Commande'
    WHEN 'cowrie.session.file_upload'   THEN '📤 Upload malware'
    WHEN 'cowrie.session.file_download' THEN '📥 Download'
    WHEN '1001'  THEN '🔐 SSH (tentative)'
    WHEN '2000'  THEN '📟 Telnet login'
    WHEN '3000'  THEN '📁 FTP login'
    WHEN '8001'  THEN '🗄️ MySQL login'
    WHEN '12001' THEN '🖱️ VNC'
    WHEN '14001' THEN '🖥️ RDP login'
    ELSE event_type
  END AS type_label,
  username,
  password,
  message
FROM events
WHERE src_ip IS NOT NULL AND src_ip != '' AND {TRANGE} AND {PORT_F}
ORDER BY ts DESC
LIMIT 300
"""
journal = panel(14, "📋 Journal des Attaques en Temps Réel", "table",
    {"h":12,"w":24,"x":0,"y":37},
    [tbl("A", journal_sql)],
    {"cellHeight":"sm","footer":{"show":False},"showHeader":True,"sortBy":[{"desc":True,"displayName":"Heure"}]},
    journal_fc)

# ── Commandes & upload ────────────────────────────────────────────────────────
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

# ── Row: Surveillance ports ───────────────────────────────────────────────────
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

# Timeseries par port (FIX GROUP BY)  
ts_port_sql = f"""
SELECT
  {BUCKET} AS time,
  SUM(CASE WHEN dst_port=22   THEN 1 ELSE 0 END) AS "SSH 22",
  SUM(CASE WHEN dst_port=23   THEN 1 ELSE 0 END) AS "Telnet 23",
  SUM(CASE WHEN dst_port=21   THEN 1 ELSE 0 END) AS "FTP 21",
  SUM(CASE WHEN dst_port=80   THEN 1 ELSE 0 END) AS "HTTP 80",
  SUM(CASE WHEN dst_port=3306 THEN 1 ELSE 0 END) AS "MySQL 3306",
  SUM(CASE WHEN dst_port=3389 THEN 1 ELSE 0 END) AS "RDP 3389",
  SUM(CASE WHEN dst_port=5900 THEN 1 ELSE 0 END) AS "VNC 5900"
FROM events
WHERE dst_port > 0 AND {TRANGE} AND {PORT_F}
GROUP BY {GRP5}
ORDER BY 1 ASC
"""
ts_ports = panel(18, "📡 Activité par Port dans le Temps", "timeseries",
    {"h":8,"w":12,"x":12,"y":60},
    [ts("A", ts_port_sql)],
    {"legend":{"calcs":["sum"],"displayMode":"table","placement":"right","showLegend":True},"tooltip":{"mode":"multi","sort":"desc"}},
    {"defaults":{"color":{"mode":"palette-classic"},"custom":{"fillOpacity":12,"lineWidth":2,"spanNulls":True}},"overrides":[]})

recap_sql = f"""
SELECT
  {port_label} AS port_service,
  COUNT(*)                          AS total,
  COUNT(DISTINCT src_ip)            AS ips_uniques,
  MIN(timestamp)                    AS premiere,
  MAX(timestamp)                    AS derniere
FROM events
WHERE dst_port > 0 AND {TRANGE} AND {PORT_F}
GROUP BY dst_port
ORDER BY total DESC
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

# ── Dashboard final ───────────────────────────────────────────────────────────
dashboard = {
    "uid":          DASH_UID,
    "title":        "🍯 Honeypot Dashboard",
    "description":  "Honeypot Dashboard — Cowrie + OpenCanary → PostgreSQL",
    "tags":         ["honeypot", "security", "cowrie", "opencanary"],
    "editable":     True,
    "graphTooltip": 1,
    "refresh":      "5s",
    "schemaVersion": 42,
    "time":         {"from": "now-24h", "to": "now"},
    "timepicker":   {},
    "timezone":     "browser",
    "annotations": {"list": []},
    "links":        [],
    "panels": [
        stat_connexions, stat_ips, stat_logins_ok, stat_cmds, stat_uploads, stat_logins_fail,
        ts_activite,
        top_ips, donut_proto,
        logins_ip, top_cmds,
        top_users, top_pass,
        journal,
        cmds_table, uploads_table,
        row_ports, bar_ports, ts_ports, recap_ports,
    ],
    "templating": {"list": [PORT_VAR]},
    "version": 1,
}

print("[GF] Envoi du dashboard vers Grafana …")
result = gf_post("/api/dashboards/db", {"dashboard": dashboard, "overwrite": True, "folderId": 0})
print(f"[GF] Résultat : status={result.get('status')}  url={result.get('url')}")

# Sauvegarde locale
out = "/tmp/honeypot-dashboard-optimized.json"
with open(out, "w") as f:
    json.dump(dashboard, f, indent=2, ensure_ascii=False)
print(f"[GF] JSON sauvegardé → {out}")
print("\n✅ Optimisation terminée.")
