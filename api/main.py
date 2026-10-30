"""
API de honeypot-map.

Lancement (depuis la racine du projet) :
    python -m uvicorn api.main:app --reload

Variables d'environnement (toutes optionnelles) :
    DB_PATH        chemin de la base SQLite        (défaut : data/honeypot.db)
    REPLAY=1       rejoue en boucle les événements existants (démo sans honeypot)
    SHOW_FULL_IPS=1  affiche les IP complètes (développement local uniquement)

Documentation interactive : http://127.0.0.1:8000/docs
"""
import asyncio
import os
import random
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from . import db

DB_PATH = os.environ.get("DB_PATH", "data/honeypot.db")
REPLAY = os.environ.get("REPLAY") == "1"
WEB_DIR = Path("web")

app = FastAPI(title="honeypot-map API", version="0.1.0")


def get_conn():
    try:
        return db.connect(DB_PATH)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"{exc}. Lance d'abord ingest.py.")


@app.get("/api/health")
def health():
    return {"status": "ok", "replay_mode": REPLAY, "db": DB_PATH}


@app.get("/api/summary")
def summary():
    with closing(get_conn()) as conn:
        return db.summary(conn)


@app.get("/api/countries")
def countries(limit: int = Query(10, ge=1, le=100)):
    with closing(get_conn()) as conn:
        return db.top_countries(conn, limit)


@app.get("/api/passwords")
def passwords(limit: int = Query(10, ge=1, le=100)):
    with closing(get_conn()) as conn:
        return db.top_passwords(conn, limit)


@app.get("/api/usernames")
def usernames(limit: int = Query(10, ge=1, le=100)):
    with closing(get_conn()) as conn:
        return db.top_usernames(conn, limit)


@app.get("/api/commands")
def commands(limit: int = Query(10, ge=1, le=100)):
    with closing(get_conn()) as conn:
        return db.top_commands(conn, limit)


@app.get("/api/ips")
def ips(limit: int = Query(10, ge=1, le=100)):
    with closing(get_conn()) as conn:
        return db.top_ips(conn, limit)


@app.get("/api/timeline")
def timeline(days: int = Query(7, ge=1, le=90)):
    with closing(get_conn()) as conn:
        return db.timeline(conn, days)


@app.get("/api/attacks/recent")
def recent_attacks(limit: int = Query(50, ge=1, le=500)):
    with closing(get_conn()) as conn:
        return db.recent_attacks(conn, limit)


@app.websocket("/ws/attacks")
async def ws_attacks(ws: WebSocket):
    """Pousse chaque nouvel événement d'attaque dès qu'il arrive en base.

    En mode REPLAY, rejoue les événements existants en boucle à vitesse réelle
    accélérée, ce qui permet de tester le dashboard avec les données d'exemple.
    """
    await ws.accept()
    try:
        conn = db.connect(DB_PATH)
    except FileNotFoundError:
        await ws.close(code=1011)
        return
    try:
        last_id = 0 if REPLAY else db.max_id(conn)
        while True:
            events = db.new_events(conn, last_id, 100)
            if not events:
                if REPLAY:
                    last_id = 0  # fin des données : on recommence
                await asyncio.sleep(1.0)
                continue
            for event in events:
                await ws.send_json(event)
                last_id = event["id"]
                if REPLAY:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
            if not REPLAY:
                await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    finally:
        conn.close()


# Le dashboard (jour 5) sera servi depuis web/ dès que web/index.html existera.
if (WEB_DIR / "index.html").is_file():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
else:
    @app.get("/")
    def root():
        return {"message": "honeypot-map API", "docs": "/docs"}
