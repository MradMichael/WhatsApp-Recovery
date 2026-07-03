"""
Creates two minimal WhatsApp-schema SQLite databases in work/
so you can test the merge pipeline (phases 2 & 3) without real phone files.

Run:  python create_test_data.py
Then: python test_merge.py
"""
import sqlite3, os, random, time
from pathlib import Path

WORK = Path("work")
WORK.mkdir(exist_ok=True)

# ── shared schema builder ──────────────────────────────────────────────────────
def build_schema(con):
    con.executescript("""
    PRAGMA user_version = 8;
    PRAGMA foreign_keys = OFF;

    CREATE TABLE IF NOT EXISTS jid (
        _id          INTEGER PRIMARY KEY AUTOINCREMENT,
        raw_string   TEXT NOT NULL UNIQUE,
        server       TEXT,
        agent        INTEGER DEFAULT 0,
        device       INTEGER DEFAULT 0,
        user         TEXT,
        is_me        INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS chat (
        _id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        jid_row_id              INTEGER NOT NULL UNIQUE,
        hidden                  INTEGER DEFAULT 0,
        subject                 TEXT,
        created_timestamp       INTEGER,
        display_message_row_id  INTEGER,
        last_message_row_id     INTEGER
    );

    CREATE TABLE IF NOT EXISTS message (
        _id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_row_id          INTEGER NOT NULL,
        from_me              INTEGER DEFAULT 0,
        timestamp            INTEGER,
        received_timestamp   INTEGER,
        sender_jid_row_id    INTEGER,
        text_data            TEXT,
        status               INTEGER DEFAULT 0,
        broadcast            INTEGER DEFAULT 0,
        message_type         INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS message_text (
        _id              INTEGER PRIMARY KEY,
        message_row_id   INTEGER NOT NULL,
        description      TEXT,
        page_title       TEXT
    );

    CREATE TABLE IF NOT EXISTS message_media (
        _id              INTEGER PRIMARY KEY,
        message_row_id   INTEGER NOT NULL,
        file_path        TEXT,
        file_size        INTEGER,
        mime_type        TEXT,
        chat_row_id      INTEGER
    );

    CREATE TABLE IF NOT EXISTS receipt_user (
        _id                      INTEGER PRIMARY KEY AUTOINCREMENT,
        message_row_id           INTEGER NOT NULL,
        receipt_user_jid_row_id  INTEGER,
        status                   INTEGER DEFAULT 1,
        timestamp                INTEGER
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS message_ftsv2
        USING fts4(content="message", text_data);
    """)
    con.commit()


# ── seed data ─────────────────────────────────────────────────────────────────
def ms(year, month=6, day=15):
    import datetime
    dt = datetime.datetime(year, month, day, 12, 0, 0)
    return int(dt.timestamp() * 1000)


def seed(con, label, years, id_start=1):
    """Insert sample JIDs, chats, and messages."""
    jids = []
    contacts = [
        ("alice@s.whatsapp.net", "Alice"),
        ("bob@s.whatsapp.net",   "Bob"),
        ("carol@s.whatsapp.net", "Carol"),
    ]
    for raw, name in contacts:
        cur = con.execute(
            "INSERT OR IGNORE INTO jid(raw_string, server, user) VALUES(?,?,?)",
            (raw, "s.whatsapp.net", name)
        )
        jids.append(con.execute("SELECT _id FROM jid WHERE raw_string=?", (raw,)).fetchone()[0])

    chat_ids = []
    for jid_id, (_, name) in zip(jids, contacts):
        cur = con.execute(
            "INSERT INTO chat(jid_row_id, subject, created_timestamp) VALUES(?,?,?)",
            (jid_id, name, ms(years[0]))
        )
        chat_ids.append(cur.lastrowid)

    sample_texts = [
        "Hey! How are you?",
        "Just had the best coffee ☕",
        "Are you free this weekend?",
        "Check out this photo!",
        "Long time no see!",
        "Happy birthday! 🎂",
        "Did you see the news?",
        "Miss you all ❤️",
        "When are we meeting?",
        "Good morning! 🌞",
    ]

    msg_id = id_start
    for yr in years:
        for chat_id, jid_id in zip(chat_ids, jids):
            for month in [3, 7, 11]:
                txt = random.choice(sample_texts)
                ts = ms(yr, month)
                con.execute(
                    """INSERT INTO message(_id, chat_row_id, from_me, timestamp,
                       received_timestamp, sender_jid_row_id, text_data, status)
                       VALUES(?,?,?,?,?,?,?,1)""",
                    (msg_id, chat_id, random.randint(0, 1), ts, ts + 1000, jid_id, txt)
                )
                # add a media row for every 3rd message
                if msg_id % 3 == 0:
                    path = f"Media/WhatsApp Images/IMG_{yr}{month:02d}_{msg_id:04d}.jpg"
                    con.execute(
                        """INSERT INTO message_media(_id, message_row_id, file_path,
                           file_size, mime_type, chat_row_id)
                           VALUES(?,?,?,?,?,?)""",
                        (msg_id, msg_id, path, random.randint(50000, 3000000),
                         "image/jpeg", chat_id)
                    )
                msg_id += 1

    con.commit()
    total = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
    print(f"  [{label}] {total} messages across {len(chat_ids)} chats "
          f"({years[0]}–{years[-1]})")
    return msg_id


# ── main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    random.seed(42)

    print("Creating fake old_msgstore.db (2015–2024)…")
    old_path = WORK / "old_msgstore.db"
    old_path.unlink(missing_ok=True)
    old = sqlite3.connect(str(old_path))
    build_schema(old)
    seed(old, "old", list(range(2015, 2025)), id_start=1)
    old.close()

    print("Creating fake new_msgstore.db (2025–2026)…")
    new_path = WORK / "new_msgstore.db"
    new_path.unlink(missing_ok=True)
    new = sqlite3.connect(str(new_path))
    build_schema(new)
    seed(new, "new", [2025, 2026], id_start=1)
    new.close()

    print("\nDone. Run:  python test_merge.py")
