# 🍯 HoneyPot — Guide d'administration

## Installation

Sur une machine fraîche **Ubuntu 24.04 LTS** :

```bash
wget -O install.sh https://raw.githubusercontent.com/j0k3r91/HoneyPot/master/install.sh
sudo bash install.sh
```

Le script installe et configure automatiquement (12 étapes) :
Cowrie · OpenCanary · PostgreSQL · Grafana (HTTPS) · UFW · Dashboard 20 panels

> Pour re-déployer le dashboard uniquement : `optimize.py`

---

**Serveur :** `<votre-ip>:2222`

```
ssh -p 2222 <user>@<votre-ip>
```

---

## Pare-feu UFW

```bash
# Voir l'état actuel
sudo ufw status numbered

# Modifier le port SSH admin (exemple : 2222 → 2223)
sudo ufw delete allow 2222/tcp
sudo ufw allow 2223/tcp comment "SSH admin"

# Restreindre Grafana à votre IP uniquement (recommandé en production)
sudo ufw delete allow 3000/tcp
sudo ufw allow from <votre-ip> to any port 3000 comment "Grafana (IP restreinte)"
```

| Port | Règle | Usage |
|---|---|---|
| `2222` *(configurable)* | ALLOW | SSH d'administration |
| `22` | ALLOW | Cowrie SSH (honeypot) |
| `23` | ALLOW | Cowrie Telnet (honeypot) |
| `21` | ALLOW | OpenCanary FTP |
| `80` | ALLOW | OpenCanary HTTP |
| `3306` | ALLOW | OpenCanary MySQL |
| `3389` | ALLOW | OpenCanary RDP |
| `5900` | ALLOW | OpenCanary VNC |
| `3000` | ALLOW | Grafana |

---

## Statut des services

```bash
# Vue rapide (tous les services)
systemctl is-active cowrie honeypot-parser opencanary grafana-server postgresql@16-main

# Statut détaillé d'un service
systemctl status cowrie
systemctl status honeypot-parser
systemctl status opencanary
systemctl status grafana-server
systemctl status postgresql@16-main

# Logs en temps réel
journalctl -u cowrie -f
journalctl -u honeypot-parser -f
journalctl -u opencanary -f

# Redémarrer un service
sudo systemctl restart cowrie
sudo systemctl restart honeypot-parser
```

---

## Architecture du pipeline

```
SSH/Telnet attacks
       │
  [Cowrie :22/:23] ──→ plugin pglog (Twisted/adbapi) ─────────────┐
                                                                   ▼
FTP/HTTP/MySQL/RDP/VNC attacks                              [PostgreSQL]
       │                                                    db: honeypot
  [OpenCanary] ──→ /var/log/opencanary.log                        │
                       │                                           ▼
               [honeypot-parser]                           [Grafana :3000]
               (inotify, temps réel)  ───────────────────► Dashboard HTTPS
```

---

## Fichiers de configuration

| Application | Fichier de config |
|---|---|
| **Cowrie** | `/home/cowrie/cowrie/etc/cowrie.cfg` |
| **Cowrie plugin pglog** | section `[output_pglog]` dans `cowrie.cfg` |
| **OpenCanary** | `/etc/opencanaryd/opencanary.conf` |
| **Parser OpenCanary** | `/opt/honeypot-to-postgres.py` |
| **Grafana** | `/etc/grafana/grafana.ini` |
| **PostgreSQL** | `/etc/postgresql/16/main/postgresql.conf` |

### Cowrie — ports actifs

Cowrie écoute directement sur les ports `22` (SSH) et `23` (Telnet) sans root. La capability `CAP_NET_BIND_SERVICE` est accordée **au service systemd** via `AmbientCapabilities` (scopée au processus Cowrie uniquement — aucune modification du binaire Python système) :

```ini
# /etc/systemd/system/cowrie.service
[Service]
User=cowrie
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

```ini
# /home/cowrie/cowrie/etc/cowrie.cfg
[ssh]
listen_endpoints = tcp:22:interface=0.0.0.0   # SSH
[telnet]
listen_endpoints = tcp:23:interface=0.0.0.0   # Telnet
[output_pglog]
enabled = true
host = localhost
database = honeypot
username = honeypot
password = VOTRE_MDP_PG
```

### OpenCanary — services actifs
```json
// /etc/opencanaryd/opencanary.conf
"ftp.enabled": true,       // port 21
"http.enabled": true,      // port 80
"mysql.enabled": true,     // port 3306
"rdp.enabled": true,       // port 3389
"vnc.enabled": true,       // port 5900
```

---

## Base de données PostgreSQL

```bash
# Connexion
PGPASSWORD=VOTRE_MDP_PG psql -U honeypot -h localhost honeypot

# Stats rapides
SELECT source, event_type, count(*) n FROM events GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20;

# Derniers événements
SELECT source, src_ip, event_type, to_timestamp(ts/1000.0) FROM events ORDER BY ts DESC LIMIT 10;

# Taille de la table
SELECT pg_size_pretty(pg_total_relation_size('events'));
```

---

## Grafana

- **URL :** `https://<votre-ip>:3000`  *(certificat auto-signé — ignorer l'alerte navigateur)*
- **Login :** `admin` / votre mot de passe Grafana
- **Dashboard :** `🍯 Honeypot Dashboard` (uid: `honeypot-v4`)
- **Refresh :** 5 s (automatique)

### Redéployer le dashboard depuis `optimize.py`
```bash
# Depuis le serveur :
GF_PASS=votre-mdp-grafana PG_PASS=votre-mdp-pg \
  /home/ubuntu/honeypot-parser-env/bin/python3 /home/ubuntu/optimize.py
```

---

## Healthcheck complet

```bash
# Statut de tous les services
systemctl is-active cowrie opencanary honeypot-parser grafana-server postgresql

# Ports en écoute
sudo ss -tlnp | grep -E ':22|:23|:21|:80|:3000|:3306|:3389|:5432|:5900|:2222'

# Événements en base (5 dernières minutes)
PGPASSWORD=VOTRE_MDP_PG psql -U honeypot -h localhost honeypot \
  -c "SELECT source, event_type, COUNT(*) n FROM events GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20;"

# Vérifier le plugin pglog Cowrie
sudo journalctl -u cowrie -n 20 --no-pager | grep -E 'pglog|ERROR'

# Vérifier le parser OpenCanary
sudo journalctl -u honeypot-parser -n 20 --no-pager
```

---

## Fichiers du projet (locaux)

| Fichier | Rôle |
|---|---|
| `install.sh` | Script d'installation complet (Ubuntu 24.04 LTS) — 12 étapes automatisées |
| `optimize.py` | Reconstruit et déploie le dashboard Grafana (20 panels) — embarqué dans `install.sh` |
| `test_ports.py` | Teste tous les ports honeypot (SSH, FTP, HTTP, MySQL, RDP, VNC) depuis l'extérieur |
| `honeypot-dashboard-v4.json` | Backup JSON du dashboard Grafana |

> **Mots de passe :** `install.sh` refuse les caractères `$`, `` ` ``, `\`, `"` et `'` (incompatibles avec les heredocs bash, SQL et JSON internes). Utilisez des caractères alphanumériques et `@`, `!`, `#`, `%`, `+`, `-`, `=`.

---

## Dépannage rapide

```bash
# Plugin pglog ne démarre pas
sudo grep -a 'pglog' /home/cowrie/cowrie/var/log/cowrie/cowrie.log | tail -10

# Parser OpenCanary bloqué
journalctl -u honeypot-parser --since "10 min ago" --no-pager

# Mot de passe PostgreSQL du parser (si modifié)
echo 'PG_PASS=NOUVEAU_MDP' | sudo tee /etc/honeypot-parser.env
sudo chmod 600 /etc/honeypot-parser.env
sudo systemctl restart honeypot-parser

# Pas de nouvelles données en DB
# → vérifier position file
sudo cat /var/lib/honeypot-pos.json

# Réinitialiser la position de lecture OpenCanary (force re-parse)
echo '{"cowrie": 0, "opencanary": 0}' | sudo tee /var/lib/honeypot-pos.json
sudo systemctl restart honeypot-parser

# Cowrie n'insère plus en DB (plugin pglog)
sudo grep -a pglog /home/cowrie/cowrie/var/log/cowrie/cowrie.log | tail -10
sudo systemctl restart cowrie

# Reset mot de passe Grafana admin
sudo grafana-cli admin reset-admin-password NOUVEAU_MDP
```

---

## Logtypes OpenCanary

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
