"""
Accès aux données de honeypot-map (SQLite, en lecture seule).

Ce module ne dépend ni de FastAPI ni d'aucune bibliothèque externe :
il peut être testé seul. Par défaut, les adresses IP sont masquées
(dernier octet) dans tout ce qui sort de l'API ; mets SHOW_FULL_IPS=1
pour les afficher en développement local.
"""
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

ATTACK_EVENTS = (
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
)
SHORT_TYPES = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
}
_ATTACK_IN = ",".join(f"'{e}'" for e in ATTACK_EVENTS)
_LOGIN_IN = "'cowrie.login.failed','cowrie.login.success'"


def connect(db_path):
    """Ouvre la base en lecture seule (l'API ne doit jamais écrire)."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Base introuvable : {db_path}")
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _has_geo(conn):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ip_info'"
    ).fetchone()
    return row is not None


def mask_ip(ip):
    """192.168.12.34 -> 192.168.12.x   |   2001:db8:1:2::5 -> 2001:db8::x"""
    if ip is None or os.environ.get("SHOW_FULL_IPS") == "1":
        return ip
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + "::x"
    parts = ip.split(".")
    return ".".join(parts[:3] + ["x"]) if len(parts) == 4 else ip


def _event_select(conn):
    if _has_geo(conn):
        return (
            "SELECT e.id, e.ts, e.eventid, e.session, e.src_ip, e.username, e.password, "
            "e.command, e.url, i.country_code, i.country, i.city, i.latitude, i.longitude "
            "FROM events e LEFT JOIN ip_info i ON i.ip = e.src_ip "
        )
    return (
        "SELECT e.id, e.ts, e.eventid, e.session, e.src_ip, e.username, e.password, "
        "e.command, e.url, NULL AS country_code, NULL AS country, NULL AS city, "
        "NULL AS latitude, NULL AS longitude FROM events e "
    )


def _to_event(row):
    return {
        "id": row["id"],
        "ts": row["ts"],
        "type": SHORT_TYPES.get(row["eventid"], row["eventid"]),
        "session": row["session"],
        "ip": mask_ip(row["src_ip"]),
        "country_code": row["country_code"],
        "country": row["country"],
        "city": row["city"],
        "lat": row["latitude"],
        "lon": row["longitude"],
        "username": row["username"],
        "password": row["password"],
        "command": row["command"],
        "url": row["url"],
    }


def max_id(conn):
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]


def new_events(conn, after_id, limit=100):
    """Événements d'attaque plus récents que after_id (ordre d'insertion)."""
    rows = conn.execute(
        _event_select(conn)
        + f"WHERE e.id > ? AND e.eventid IN ({_ATTACK_IN}) ORDER BY e.id LIMIT ?",
        (after_id, limit),
    ).fetchall()
    return [_to_event(r) for r in rows]


def recent_attacks(conn, limit=50):
    rows = conn.execute(
        _event_select(conn)
        + f"WHERE e.eventid IN ({_ATTACK_IN}) ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_to_event(r) for r in rows]


def summary(conn):
    r = conn.execute(
        """SELECT COUNT(*) AS total,
                  COUNT(DISTINCT src_ip) AS ips,
                  COUNT(DISTINCT session) AS sessions,
                  COALESCE(SUM(eventid = 'cowrie.session.connect'), 0) AS connections,
                  COALESCE(SUM(eventid = 'cowrie.login.failed'), 0) AS login_failed,
                  COALESCE(SUM(eventid = 'cowrie.login.success'), 0) AS login_success,
                  COALESCE(SUM(eventid = 'cowrie.command.input'), 0) AS commands,
                  COALESCE(SUM(eventid = 'cowrie.session.file_download'), 0) AS downloads,
                  MIN(ts) AS first_event, MAX(ts) AS last_event
           FROM events"""
    ).fetchone()
    data = dict(r)
    data["countries"] = 0
    if _has_geo(conn):
        data["countries"] = conn.execute(
            "SELECT COUNT(DISTINCT country_code) FROM ip_info WHERE country_code IS NOT NULL"
        ).fetchone()[0]
    return data


def top_countries(conn, limit=10):
    if not _has_geo(conn):
        return []
    rows = conn.execute(
        """SELECT i.country_code, i.country,
                  COUNT(DISTINCT e.src_ip) AS ips,
                  COALESCE(SUM(e.eventid = 'cowrie.session.connect'), 0) AS attacks
           FROM events e JOIN ip_info i ON i.ip = e.src_ip
           WHERE i.country_code IS NOT NULL
           GROUP BY i.country_code ORDER BY attacks DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def _top(conn, column, where, limit):
    # `column` et `where` viennent du code ci-dessous, jamais de l'utilisateur.
    rows = conn.execute(
        f"""SELECT {column} AS value, COUNT(*) AS n FROM events
            WHERE {where} AND {column} IS NOT NULL
            GROUP BY {column} ORDER BY n DESC, value LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def top_passwords(conn, limit=10):
    return _top(conn, "password", f"eventid IN ({_LOGIN_IN})", limit)


def top_usernames(conn, limit=10):
    return _top(conn, "username", f"eventid IN ({_LOGIN_IN})", limit)


def top_commands(conn, limit=10):
    return _top(conn, "command", "eventid = 'cowrie.command.input'", limit)


def top_ips(conn, limit=10):
    if _has_geo(conn):
        sql = """SELECT e.src_ip AS ip, COUNT(*) AS n, i.country AS country
                 FROM events e LEFT JOIN ip_info i ON i.ip = e.src_ip
                 WHERE e.src_ip IS NOT NULL GROUP BY e.src_ip ORDER BY n DESC LIMIT ?"""
    else:
        sql = """SELECT src_ip AS ip, COUNT(*) AS n, NULL AS country FROM events
                 WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT ?"""
    return [
        {"ip": mask_ip(r["ip"]), "n": r["n"], "country": r["country"]}
        for r in conn.execute(sql, (limit,)).fetchall()
    ]


def timeline(conn, days=7):
    """Nombre de connexions par heure, sur les `days` derniers jours de données."""
    last = conn.execute("SELECT MAX(ts) FROM events").fetchone()[0]
    if last is None:
        return []
    end = datetime.fromisoformat(last.replace("Z", "+00:00"))
    cutoff = (end - timedelta(days=days)).strftime("%Y-%m-%dT%H")
    rows = conn.execute(
        """SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS n FROM events
           WHERE eventid = 'cowrie.session.connect' AND substr(ts, 1, 13) >= ?
           GROUP BY hour ORDER BY hour""",
        (cutoff,),
    ).fetchall()
    return [{"hour": r["hour"] + ":00:00Z", "n": r["n"]} for r in rows]
