#!/usr/bin/env python3
"""
Génère un rapport d'analyse (Markdown) à partir de la base SQLite du honeypot.

Usage :
    python analysis/report.py --db data/prod.db --exclude-ip 203.0.113.7

Points importants :
  - --exclude-ip (répétable) retire tes propres tests des statistiques.
  - Les adresses IP sont masquées (dernier octet) dans le rapport.
  - Tout ce qui vient des attaquants (mots de passe, commandes, URL) est traité
    comme une donnée non fiable : neutralisé avant d'être écrit dans le Markdown,
    et les URL sont "défanguées" (hxxp, [.]) pour qu'aucun lien ne soit cliquable.
  - La base est ouverte en lecture seule.
"""
import argparse
import ipaddress
import re
import sqlite3
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

LOGIN_EVENTS = "('cowrie.login.failed','cowrie.login.success')"

# Première catégorie qui correspond : l'ordre compte.
CATEGORIES = [
    ("Persistance (clés SSH, cron)", r"authorized_keys|crontab|rc\.local|systemctl\s+enable|useradd|adduser"),
    ("Téléchargement / exécution", r"\b(wget|curl|tftp|ftpget|scp)\b|chmod\s+\S*x|\./\S+|\b(sh|bash)\s+\S+"),
    ("Minage / malware connu", r"xmrig|minerd|cpuminer|stratum|kinsing|kdevtmpfsi"),
    ("Nettoyage de traces", r"rm\s+-rf|history\s+-c|unset\s+HISTFILE|/var/log"),
    ("Reconnaissance système",
     r"uname|/proc/|lscpu|\bfree\b|\bdf\b|nproc|whoami|^id$|^w$|\bps\b|/etc/(passwd|issue|os-release|shadow)|ifconfig|hostname|^ls\b|^cat\b|^pwd$|^uptime"),
]


# ---------- utilitaires de mise en forme (les données viennent d'attaquants) ----------
def _defang_url(match):
    url = match.group(0)
    url = ("fxp" + url[3:]) if url.lower().startswith("ftp") else ("hxxp" + url[4:])
    return url.replace(".", "[.]")


def code(value, width=70):
    """Texte non fiable -> code inline Markdown sûr."""
    s = "" if value is None else str(value)
    s = re.sub(r"[\x00-\x1f\x7f]", lambda m: "\\x%02x" % ord(m.group()), s)
    s = s.replace("`", "'").replace("|", "¦")
    # URL cachées dans une commande ou un mot de passe : on les défangue aussi
    s = re.sub(r"(?i)\b(?:https?|ftp)://\S+", _defang_url, s)
    if len(s) > width:
        s = s[: width - 1] + "…"
    return f"`{s}`"


def defang(url, width=80):
    u = (url or "").replace("http", "hxxp", 1).replace(".", "[.]")
    return code(u, width)


def mask_ip(ip):
    if not ip:
        return ""
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + "::x"
    parts = ip.split(".")
    return ".".join(parts[:3] + ["x"]) if len(parts) == 4 else ip


def bar(n, biggest, width=20):
    return "█" * int(round(width * n / biggest)) if biggest else ""


def table(headers, rows):
    if not rows:
        return ["_Aucune donnée._", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out + [""]


def pct(a, b):
    return f"{100 * a / b:.1f} %" if b else "–"


# ---------- accès aux données ----------
def open_db(path):
    p = Path(path)
    if not p.is_file():
        sys.exit(f"Base introuvable : {path}")
    conn = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def make_view(conn, excluded):
    """Vue temporaire `ev` = événements sans les IP exclues."""
    where = ""
    if excluded:
        ips = ",".join(f"'{ipaddress.ip_address(ip)}'" for ip in excluded)  # valide chaque IP
        where = f"WHERE src_ip IS NULL OR src_ip NOT IN ({ips})"
    conn.execute(f"CREATE TEMP VIEW ev AS SELECT * FROM events {where}")


def has_geo(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE name='ip_info'").fetchone() is not None


def one(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()[0] or 0


# ---------- sections ----------
def section_summary(conn):
    r = conn.execute(
        """SELECT COUNT(*) total, COUNT(DISTINCT src_ip) ips, COUNT(DISTINCT session) sessions,
                  SUM(eventid='cowrie.session.connect') conn, SUM(eventid='cowrie.login.failed') failed,
                  SUM(eventid='cowrie.login.success') ok, SUM(eventid='cowrie.command.input') cmds,
                  SUM(eventid='cowrie.session.file_download') dl, MIN(ts) first, MAX(ts) last FROM ev"""
    ).fetchone()
    if not r["total"]:
        return None, ["_La base ne contient aucun événement (après exclusions)._", ""]
    t0 = datetime.fromisoformat(r["first"].replace("Z", "+00:00"))
    t1 = datetime.fromisoformat(r["last"].replace("Z", "+00:00"))
    days = max((t1 - t0).total_seconds() / 86400, 0.01)
    with_ok = one(conn, "SELECT COUNT(DISTINCT session) FROM ev WHERE eventid='cowrie.login.success'")
    with_cmd = one(conn, "SELECT COUNT(DISTINCT session) FROM ev WHERE eventid='cowrie.command.input'")
    repeat = one(conn, """SELECT COUNT(*) FROM (SELECT src_ip FROM ev WHERE eventid='cowrie.session.connect'
                          GROUP BY src_ip HAVING COUNT(*) > 1)""")
    multi_day = one(conn, """SELECT COUNT(*) FROM (SELECT src_ip FROM ev WHERE eventid='cowrie.session.connect'
                             GROUP BY src_ip HAVING COUNT(DISTINCT substr(ts,1,10)) > 1)""")
    durations = [x[0] for x in conn.execute(
        "SELECT duration FROM ev WHERE eventid='cowrie.session.closed' AND duration IS NOT NULL")]
    med = f"{statistics.median(durations):.1f} s" if durations else "–"
    rows = [
        ("Période observée", f"{r['first'][:16]} → {r['last'][:16]} UTC ({days:.1f} jours)"),
        ("Connexions (sessions SSH)", f"{r['conn']:,}".replace(",", " ")),
        ("Adresses IP uniques", f"{r['ips']:,}".replace(",", " ")),
        ("Tentatives de connexion", f"{r['failed'] + r['ok']:,}".replace(",", " ")),
        ("Connexions « réussies » (faux accès accordé)", f"{r['ok']:,}".replace(",", " ")),
        ("Sessions avec connexion réussie", f"{with_ok} ({pct(with_ok, r['sessions'])})"),
        ("Sessions avec commandes tapées", f"{with_cmd} ({pct(with_cmd, r['sessions'])})"),
        ("Commandes enregistrées", f"{r['cmds']:,}".replace(",", " ")),
        ("Téléchargements de fichiers", f"{r['dl']}"),
        ("IP revenues au moins une fois", f"{repeat} ({pct(repeat, r['ips'])})"),
        ("IP actives sur plusieurs jours", f"{multi_day} ({pct(multi_day, r['ips'])})"),
        ("Durée médiane d'une session", med),
        ("Rythme moyen", f"{r['conn'] / days:.0f} connexions par jour"),
    ]
    return r, ["## 1. Résumé", ""] + table(["Indicateur", "Valeur"], rows)


def section_origin(conn):
    out = ["## 2. Origine des attaques", ""]
    if not has_geo(conn):
        return out + ["_Géolocalisation absente : lance `geoip_enrich.py` avant d'analyser._", ""]
    rows = conn.execute(
        """SELECT COALESCE(i.country,'Inconnu') c, COUNT(DISTINCT e.src_ip) ips,
                  SUM(e.eventid='cowrie.session.connect') n
           FROM ev e LEFT JOIN ip_info i ON i.ip = e.src_ip WHERE e.src_ip IS NOT NULL
           GROUP BY i.country_code ORDER BY n DESC LIMIT 10""").fetchall()
    big = max([r["n"] for r in rows] or [0])
    out += ["### Top 10 pays", ""] + table(
        ["Pays", "IP", "Connexions", ""], [(r["c"], r["ips"], r["n"], bar(r["n"], big)) for r in rows])
    rows = conn.execute(
        """SELECT COALESCE(i.asn_org,'Inconnu') org, i.asn asn, COUNT(DISTINCT e.src_ip) ips,
                  SUM(e.eventid='cowrie.session.connect') n
           FROM ev e LEFT JOIN ip_info i ON i.ip = e.src_ip WHERE e.src_ip IS NOT NULL
           GROUP BY i.asn ORDER BY n DESC LIMIT 10""").fetchall()
    out += ["### Top 10 réseaux (ASN)", ""] + table(
        ["Réseau", "ASN", "IP", "Connexions"], [(code(r["org"], 50), r["asn"] or "–", r["ips"], r["n"]) for r in rows])
    return out


def section_credentials(conn):
    out = ["## 3. Identifiants testés", ""]
    n_pw = one(conn, f"SELECT COUNT(DISTINCT password) FROM ev WHERE eventid IN {LOGIN_EVENTS}")
    n_us = one(conn, f"SELECT COUNT(DISTINCT username) FROM ev WHERE eventid IN {LOGIN_EVENTS}")
    out += [f"{n_pw} mots de passe distincts et {n_us} noms d'utilisateur distincts ont été essayés.", ""]
    for title, col, hdr in (("Top 15 mots de passe", "password", "Mot de passe"),
                            ("Top 10 noms d'utilisateur", "username", "Utilisateur")):
        lim = 15 if col == "password" else 10
        rows = conn.execute(
            f"""SELECT {col} v, COUNT(*) n FROM ev WHERE eventid IN {LOGIN_EVENTS} AND {col} IS NOT NULL
                GROUP BY {col} ORDER BY n DESC, v LIMIT {lim}""").fetchall()
        big = max([r["n"] for r in rows] or [0])
        out += [f"### {title}", ""] + table([hdr, "Essais", ""], [(code(r["v"]), r["n"], bar(r["n"], big)) for r in rows])
    rows = conn.execute(
        f"""SELECT username u, password p, COUNT(*) n FROM ev WHERE eventid IN {LOGIN_EVENTS}
            GROUP BY u, p ORDER BY n DESC LIMIT 10""").fetchall()
    out += ["### Top 10 couples utilisateur / mot de passe", ""] + table(
        ["Utilisateur", "Mot de passe", "Essais"], [(code(r["u"]), code(r["p"]), r["n"]) for r in rows])
    return out


def categorize(command):
    for name, pattern in CATEGORIES:
        if re.search(pattern, command or "", re.IGNORECASE):
            return name
    return "Autre"


def section_commands(conn):
    out = ["## 4. Comportement après la « compromission »", ""]
    rows = conn.execute(
        """SELECT command c, COUNT(*) n, COUNT(DISTINCT session) s FROM ev
           WHERE eventid='cowrie.command.input' AND command IS NOT NULL
           GROUP BY command ORDER BY n DESC LIMIT 15""").fetchall()
    out += ["### Top 15 commandes", ""] + table(
        ["Commande", "Occurrences", "Sessions"], [(code(r["c"]), r["n"], r["s"]) for r in rows])
    per_cat = {}
    for r in conn.execute("SELECT session, command FROM ev WHERE eventid='cowrie.command.input' AND command IS NOT NULL"):
        per_cat.setdefault(categorize(r["command"]), set()).add(r["session"])
    total = len({s for sess in per_cat.values() for s in sess})
    rows = sorted(((k, len(v)) for k, v in per_cat.items()), key=lambda x: -x[1])
    out += ["### Objectifs observés (sessions par catégorie)", "",
            "Classification automatique par mots-clés ; une session peut relever de plusieurs catégories.", ""]
    out += table(["Catégorie", "Sessions", "Part"], [(k, n, pct(n, total)) for k, n in rows])
    return out


def section_downloads(conn):
    out = ["## 5. Fichiers téléchargés par les bots", ""]
    n = one(conn, "SELECT COUNT(DISTINCT shasum) FROM ev WHERE eventid='cowrie.session.file_download'")
    out += [f"{n} fichier(s) distinct(s) (par empreinte SHA-256). Les fichiers ne sont jamais exécutés ni publiés ; "
            "seules les empreintes sont conservées. Les URL sont défanguées.", ""]
    rows = conn.execute(
        """SELECT url, shasum, COUNT(*) n FROM ev WHERE eventid='cowrie.session.file_download'
           GROUP BY url, shasum ORDER BY n DESC LIMIT 15""").fetchall()
    return out + table(["URL (défanguée)", "SHA-256", "Fois"],
                       [(defang(r["url"]), code(r["shasum"], 64), r["n"]) for r in rows])


def section_time(conn):
    out = ["## 6. Chronologie", ""]
    days = conn.execute("""SELECT substr(ts,1,10) d, COUNT(*) n FROM ev WHERE eventid='cowrie.session.connect'
                           GROUP BY d ORDER BY d""").fetchall()
    big = max([r["n"] for r in days] or [0])
    out += ["### Connexions par jour (UTC)", ""] + table(
        ["Jour", "Connexions", ""], [(r["d"], r["n"], bar(r["n"], big)) for r in days])
    hours = dict(conn.execute("""SELECT CAST(substr(ts,12,2) AS INTEGER) h, COUNT(*) FROM ev
                                 WHERE eventid='cowrie.session.connect' GROUP BY h""").fetchall())
    big = max(hours.values() or [0]) if hours else 0
    out += ["### Connexions par heure de la journée (UTC, tous jours confondus)", ""] + table(
        ["Heure", "Connexions", ""], [(f"{h:02d}h", hours.get(h, 0), bar(hours.get(h, 0), big)) for h in range(24)])
    return out


def section_clients(conn):
    rows = conn.execute(
        """SELECT client_version v, COUNT(*) n FROM ev WHERE eventid='cowrie.client.version' AND client_version IS NOT NULL
           GROUP BY v ORDER BY n DESC LIMIT 10""").fetchall()
    out = ["## 7. Logiciels clients SSH", "",
           "La bannière SSH annoncée par le client trahit souvent l'outil utilisé (bibliothèque d'automatisation, scanner…).", ""]
    return out + table(["Bannière du client", "Sessions"], [(code(r["v"]), r["n"]) for r in rows])


def section_top_ips(conn):
    rows = conn.execute(
        """SELECT src_ip ip, COUNT(DISTINCT session) s, COUNT(*) n,
                  COUNT(DISTINCT substr(ts,1,10)) d, MIN(ts) first, MAX(ts) last
           FROM ev WHERE src_ip IS NOT NULL
           GROUP BY src_ip ORDER BY n DESC, first LIMIT 10""").fetchall()
    out = ["## 8. Sources les plus actives", "", "Adresses masquées (dernier octet).", ""]
    out += table(["IP", "Sessions", "Événements", "Jours actifs", "Première activité (UTC)", "Dernière activité (UTC)"],
                 [(code(mask_ip(r["ip"])), r["s"], r["n"], r["d"], _minute(r["first"]), _minute(r["last"]))
                  for r in rows])
    masked = [mask_ip(r["ip"]) for r in rows]
    repeated = sorted({m for m in masked if masked.count(m) > 1})
    if repeated:
        out += ["Plusieurs lignes portant la même adresse masquée ("
                + ", ".join(code(m) for m in repeated)
                + ") correspondent à des adresses distinctes d'un même réseau, "
                  "différenciées ici par leur période d'activité.", ""]
    return out


def _minute(ts):
    """2026-10-31T14:46:38.963384Z -> 2026-10-31 14:46"""
    return ts[:16].replace("T", " ") if ts else "–"


def build(conn, excluded):
    summary, sec1 = section_summary(conn)
    title = ["# Rapport d'analyse du honeypot", "",
             f"_Généré le {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC. "
             f"{len(excluded)} adresse(s) IP exclue(s) (tests de l'auteur)._", ""]
    if summary is None:
        return "\n".join(title + sec1)
    parts = title + sec1
    for fn in (section_origin, section_credentials, section_commands, section_downloads,
               section_time, section_clients, section_top_ips):
        parts += fn(conn)
    parts += [
        "## Méthodologie et limites", "",
        "- Données issues d'**un seul** honeypot SSH (Cowrie) hébergé chez un fournisseur cloud : "
        "les résultats reflètent ce que les bots ciblent sur ce type d'adresse, pas Internet dans son ensemble.",
        "- Le honeypot accepte des identifiants « faibles » pour observer ce que font les attaquants ensuite ; "
        "les connexions réussies sont simulées.",
        "- Géolocalisation approximative (GeoLite2 de MaxMind, https://www.maxmind.com) : "
        "une IP peut appartenir à un hébergeur sans refléter l'origine réelle de l'attaquant.",
        "- Les catégories de commandes sont détectées par mots-clés et peuvent se tromper.",
        "- Adresses IP masquées ; aucun fichier malveillant n'est publié ni exécuté.", ""]
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Rapport d'analyse du honeypot (Markdown).")
    ap.add_argument("--db", default="data/honeypot.db")
    ap.add_argument("--exclude-ip", action="append", default=[], metavar="IP",
                    help="IP à exclure (répétable) : tes propres tests")
    ap.add_argument("--out", help="fichier de sortie (défaut : reports/report-AAAA-MM-JJ.md)")
    args = ap.parse_args()

    for ip in args.exclude_ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            sys.exit(f"Adresse IP invalide : {ip}")

    conn = open_db(args.db)
    make_view(conn, args.exclude_ip)
    report = build(conn, args.exclude_ip)
    out = Path(args.out or f"reports/report-{datetime.now(timezone.utc):%Y-%m-%d}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8", newline="\n")
    print(f"Rapport écrit dans {out}")
    conn.close()


if __name__ == "__main__":
    main()
