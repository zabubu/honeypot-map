#!/usr/bin/env python3
"""
Enrichit les adresses IP de la base honeypot avec leur localisation
(pays, ville, coordonnées) et leur réseau (ASN), à partir des bases
MaxMind GeoLite2 (fichiers .mmdb à télécharger séparément).

Usage :
    python ingester/geoip_enrich.py
    python ingester/geoip_enrich.py --city data/GeoLite2-City.mmdb --asn data/GeoLite2-ASN.mmdb

Relancer le script ne traite que les nouvelles IP.
"""
import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    sys.exit("Le module 'geoip2' est manquant. Installe-le avec :  pip install geoip2")

SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_info (
    ip           TEXT PRIMARY KEY,
    country_code TEXT,
    country      TEXT,
    city         TEXT,
    latitude     REAL,
    longitude    REAL,
    asn          INTEGER,
    asn_org      TEXT,
    looked_up_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_info_country ON ip_info(country_code);
"""


def lookup(ip, city_reader, asn_reader):
    """Renvoie un tuple (country_code, country, city, lat, lon, asn, asn_org)."""
    country_code = country = city = lat = lon = asn = asn_org = None
    try:
        r = city_reader.city(ip)
        country_code = r.country.iso_code
        country = r.country.name
        city = r.city.name
        lat = r.location.latitude
        lon = r.location.longitude
    except (geoip2.errors.AddressNotFoundError, ValueError):
        pass
    if asn_reader is not None:
        try:
            a = asn_reader.asn(ip)
            asn = a.autonomous_system_number
            asn_org = a.autonomous_system_organization
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
    return country_code, country, city, lat, lon, asn, asn_org


def enrich(conn, city_reader, asn_reader):
    pending = [row[0] for row in conn.execute(
        """SELECT DISTINCT e.src_ip FROM events e
           LEFT JOIN ip_info i ON i.ip = e.src_ip
           WHERE e.src_ip IS NOT NULL AND i.ip IS NULL"""
    )]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    located = 0
    for ip in pending:
        data = lookup(ip, city_reader, asn_reader)
        if data[0] is not None:
            located += 1
        conn.execute(
            "INSERT OR REPLACE INTO ip_info VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, *data, now),
        )
    conn.commit()
    return len(pending), located


def print_stats(conn):
    total_ips = conn.execute("SELECT COUNT(*) FROM ip_info").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM ip_info WHERE country_code IS NULL").fetchone()[0]
    print(f"\n=== Géolocalisation ===\nIP en base : {total_ips}  |  non localisées : {unknown}")

    print("\nTop 10 pays (par nombre d'événements) :")
    rows = conn.execute(
        """SELECT COALESCE(i.country, 'Inconnu'), COUNT(DISTINCT e.src_ip), COUNT(*) c
           FROM events e JOIN ip_info i ON i.ip = e.src_ip
           GROUP BY i.country_code ORDER BY c DESC LIMIT 10"""
    ).fetchall()
    for country, n_ips, n_events in rows:
        print(f"  {n_events:>6} événements  {n_ips:>3} IP  {country}")

    print("\nTop 5 réseaux (ASN) :")
    rows = conn.execute(
        """SELECT COALESCE(i.asn_org, 'Inconnu'), COUNT(*) c
           FROM events e JOIN ip_info i ON i.ip = e.src_ip
           GROUP BY i.asn ORDER BY c DESC LIMIT 5"""
    ).fetchall()
    for org, n in rows:
        print(f"  {n:>6}  {org}")


def main():
    parser = argparse.ArgumentParser(description="Ajoute pays, ville, coordonnées et ASN aux IP.")
    parser.add_argument("--db", default="data/honeypot.db")
    parser.add_argument("--city", default="data/GeoLite2-City.mmdb", help="base GeoLite2 City (.mmdb)")
    parser.add_argument("--asn", default="data/GeoLite2-ASN.mmdb", help="base GeoLite2 ASN (.mmdb), optionnelle")
    args = parser.parse_args()

    if not Path(args.db).is_file():
        sys.exit(f"Base introuvable : {args.db}. Lance d'abord ingest.py.")
    if not Path(args.city).is_file():
        sys.exit(f"Fichier GeoLite2 City introuvable : {args.city}")

    asn_reader = geoip2.database.Reader(args.asn) if Path(args.asn).is_file() else None
    if asn_reader is None:
        print("Base ASN absente : seules la position et le pays seront renseignés.")

    conn = sqlite3.connect(args.db)
    conn.executescript(SCHEMA)
    with geoip2.database.Reader(args.city) as city_reader:
        processed, located = enrich(conn, city_reader, asn_reader)
    if asn_reader is not None:
        asn_reader.close()

    print(f"IP traitées : {processed}  |  localisées : {located}")
    print_stats(conn)
    conn.close()


if __name__ == "__main__":
    main()
