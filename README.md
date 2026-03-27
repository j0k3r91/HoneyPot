# 🍯 HoneyPot — Guide d'administration

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
| `${SSH_ADMIN_PORT}` | ALLOW | SSH d'administration |
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
```ini
# /home/cowrie/cowrie/etc/cowrie.cfg
[shell]
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

- **URL :** `http://<votre-ip>:3000`
- **Login :** `admin` / votre mot de passe Grafana
- **Dashboard :** `🍯 Honeypot Dashboard` (uid: `honeypot-v4`)
- **Refresh :** 5 s (automatique)

### Redéployer le dashboard depuis `optimize.py`
```bash
# Depuis votre machine locale
scp -P 2222 optimize.py <user>@<votre-ip>:/tmp/optimize.py
ssh -p 2222 <user>@<votre-ip> "/home/<user>/honeypot-parser-env/bin/python3 /tmp/optimize.py"
```

---

## Healthcheck complet

```bash
# Depuis votre machine locale
scp -P 2222 optimize.py <user>@<votre-ip>:/tmp/optimize.py
ssh -p 2222 <user>@<votre-ip> "/home/<user>/honeypot-parser-env/bin/python3 /tmp/optimize.py"
```

---

## Fichiers du projet (locaux)

| Fichier | Rôle |
|---|---|
| `optimize.py` | Reconstruit et déploie le dashboard Grafana complet |
| `cowrie-pglog.py` | Source du plugin Cowrie → PostgreSQL (à redéployer si Cowrie est réinstallé) |
| `honeypot-parser-opencanary-only.py` | Source du parser OpenCanary (déployé sur `/opt/honeypot-to-postgres.py`) |
| `honeypot-dashboard-v4.json` | Backup du dashboard Grafana |
| `healthcheck.py` | Script de vérification complète de l'état du serveur |

---

## Dépannage rapide

```bash
# Plugin pglog ne démarre pas
sudo grep -a 'pglog' /home/cowrie/cowrie/var/log/cowrie/cowrie.log | tail -10

# Parser OpenCanary bloqué
journalctl -u honeypot-parser --since "10 min ago" --no-pager

# Pas de nouvelles données en DB
# → vérifier position file
sudo cat /var/lib/honeypot-pos.json

# Réinstaller le plugin Cowrie pglog
sudo cp /tmp/cowrie-pglog.py /home/cowrie/cowrie/src/cowrie/output/pglog.py
sudo chown cowrie:cowrie /home/cowrie/cowrie/src/cowrie/output/pglog.py
sudo systemctl restart cowrie
```
