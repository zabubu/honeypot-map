import ingest


def test_counts(tmp_path, cowrie_log):
    conn = ingest.connect(tmp_path / "t.db")
    counts = ingest.ingest_file(conn, cowrie_log)
    assert counts == {"new": 13, "dup": 0, "skip": 2, "error": 1}


def test_ingest_is_idempotent(tmp_path, cowrie_log):
    conn = ingest.connect(tmp_path / "t.db")
    ingest.ingest_file(conn, cowrie_log)
    again = ingest.ingest_file(conn, cowrie_log)
    assert again["new"] == 0
    assert again["dup"] == 13
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 13


def test_fields_are_normalized(tmp_path, cowrie_log):
    conn = ingest.connect(tmp_path / "t.db")
    ingest.ingest_file(conn, cowrie_log)
    cmd = conn.execute("SELECT * FROM events WHERE command = 'uname -a'").fetchone()
    assert cmd is not None
    cols = [c[0] for c in conn.execute("SELECT * FROM events").description]
    row = dict(zip(cols, cmd))
    assert row["eventid"] == "cowrie.command.input"
    assert row["src_ip"] == "203.0.113.10"
    assert row["session"] == "sA"
    dl = conn.execute("SELECT url, shasum FROM events WHERE eventid = 'cowrie.session.file_download'").fetchone()
    assert dl == ("http://evil.example/x.sh", "ab" * 32)
    version = conn.execute("SELECT client_version FROM events WHERE session = 'sB' AND client_version IS NOT NULL").fetchone()
    assert version == ("SSH-2.0-Go",)


def test_ingest_line_results(tmp_path):
    conn = ingest.connect(tmp_path / "t.db")
    good = '{"eventid": "cowrie.session.connect", "timestamp": "2026-01-01T00:00:00.000000Z", "src_ip": "1.2.3.4"}'
    assert ingest.ingest_line(conn, good) == "new"
    assert ingest.ingest_line(conn, good) == "dup"
    assert ingest.ingest_line(conn, "   ") == "skip"
    assert ingest.ingest_line(conn, "{pas du json") == "error"
    assert ingest.ingest_line(conn, '{"eventid": "x"}') == "skip"
