#!/usr/bin/env python3
"""
Ingester pour honeypot-map.

Lit un fichier de logs Cowrie (JSON Lines), normalise les événements et les
stocke dans une base SQLite. Relancer la commande sur le même fichier ne crée
pas de doublons.

Usage :
    python ingester/ingest.py samples/cowrie.sample.json
    python ingester/ingest.py logs/cowrie.json --follow     # suit le fichier en continu
"""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    eventid        TEXT NOT NULL,
    session        TEXT,
    src_ip         TEXT,
    src_port       INTEGER,
    username       TEXT,
    password       TEXT,
    command        TEXT,
    url            TEXT,
    shasum         TEXT,
    client_version TEXT,
    duration       REAL,
    sensor         TEXT,
    line_hash      TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
"""

INSERT = """
INSERT OR IGNORE INTO events
    (ts, eventid, session, src_ip, src_port, username, password, command,
     url, shasum, client_version, duration, sensor, line_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def connect(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def normalize(line):
    """Transforme une ligne JSON de Cowrie en tuple prêt à insérer (ou None)."""
    line = line.strip()
    if not line:
        return None
    d = json.loads(line)
    if not d.get("timestamp") or not d.get("eventid"):
        return None
    return (
        d["timestamp"],
        d["eventid"],
        d.get("session"),
        d.get("src_ip"),
        d.get("src_port"),
        d.get("username"),
        d.get("password"),
        d.get("input"),
        d.get("url"),
        d.get("shasum"),
        d.get("version"),
        d.get("duration"),
        d.get("sensor"),
        hashlib.sha1(line.encode("utf-8")).hexdigest(),
    )


def ingest_line(conn, line):
    """Renvoie 'new', 'dup', 'skip' ou 'error'."""
    try:
        row = normalize(line)
    except (json.JSONDecodeError, UnicodeError):
        return "error"
    if row is None:
        return "skip"
    cur = conn.execute(INSERT, row)
    return "new" if cur.rowcount else "dup"


def ingest_file(conn, path):
    counts = {"new": 0, "dup": 0, "skip": 0, "error": 0}
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            counts[ingest_line(conn, line)] += 1
            if i % 5000 == 0:
                conn.commit()
    conn.commit()
    return counts


def follow_file(conn, path, interval=1.0):
    """Lit le fichier existant puis attend les nouvelles lignes (comme tail -f)."""
    print(f"Suivi de {path} (Ctrl+C pour arrêter)")
    f = open(path, "r", encoding="utf-8")
    inode = os.fstat(f.fileno()).st_ino
    buffer = ""
    new = 0
    try:
        while True:
            chunk = f.readline()
            if chunk:
                buffer += chunk
                if buffer.endswith("\n"):
                    if ingest_line(conn, buffer) == "new":
                        new += 1
                        if new % 20 == 0:
                            conn.commit()
                    buffer = ""
                continue
            conn.commit()
            time.sleep(interval)
            # Fichier tronqué ou remplacé (rotation des logs) : on rouvre
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = open(path, "r", encoding="utf-8")
                inode = os.fstat(f.fileno()).st_ino
                buffer = ""
    except KeyboardInterrupt:
        conn.commit()
        print(f"\nArrêt. {new} nouveaux événements pendant le suivi.")
    finally:
        f.close()


def top(conn, sql, limit=5):
    return conn.execute(sql + f" LIMIT {limit}").fetchall()


def print_stats(conn):
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if total == 0:
        print("La base est vide.")
        return
    first, last = conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
    ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
    sessions = conn.execute("SELECT COUNT(DISTINCT session) FROM events").fetchone()[0]

    print("\n=== Résumé ===")
    print(f"Événements : {total}  |  IP uniques : {ips}  |  Sessions : {sessions}")
    print(f"Période    : {first}  ->  {last}")

    print("\nÉvénements par type :")
    for name, n in top(conn, "SELECT eventid, COUNT(*) c FROM events GROUP BY eventid ORDER BY c DESC", 20):
        print(f"  {n:>6}  {name}")

    sections = [
        ("Top 5 mots de passe testés",
         "SELECT password, COUNT(*) c FROM events WHERE password IS NOT NULL GROUP BY password ORDER BY c DESC"),
        ("Top 5 noms d'utilisateur",
         "SELECT username, COUNT(*) c FROM events WHERE username IS NOT NULL GROUP BY username ORDER BY c DESC"),
        ("Top 5 commandes tapées",
         "SELECT command, COUNT(*) c FROM events WHERE command IS NOT NULL GROUP BY command ORDER BY c DESC"),
        ("Top 5 IP les plus actives",
         "SELECT src_ip, COUNT(*) c FROM events GROUP BY src_ip ORDER BY c DESC"),
    ]
    for title, sql in sections:
        print(f"\n{title} :")
        for value, n in top(conn, sql):
            shown = value if len(value) <= 60 else value[:57] + "..."
            print(f"  {n:>6}  {shown}")


def main():
    parser = argparse.ArgumentParser(description="Ingère des logs Cowrie dans SQLite.")
    parser.add_argument("logfile", help="fichier de logs Cowrie (JSON Lines)")
    parser.add_argument("--db", default="data/honeypot.db", help="base SQLite (défaut : data/honeypot.db)")
    parser.add_argument("--follow", action="store_true", help="continuer à lire les nouvelles lignes")
    parser.add_argument("--no-stats", action="store_true", help="ne pas afficher le résumé")
    args = parser.parse_args()

    if not Path(args.logfile).is_file():
        sys.exit(f"Fichier introuvable : {args.logfile}")

    conn = connect(args.db)
    if args.follow:
        follow_file(conn, args.logfile)
    else:
        counts = ingest_file(conn, args.logfile)
        print(f"Importés : {counts['new']}  |  déjà présents : {counts['dup']}  |  "
              f"ignorés : {counts['skip']}  |  erreurs : {counts['error']}")
    if not args.no_stats:
        print_stats(conn)
    conn.close()


if __name__ == "__main__":
    main()
