"""
WhatsApp crypt15 merge pipeline — Phases 1-4.
Called from app.py; progress is delivered via the emit(phase, pct, msg) callback.
"""
import sqlite3, subprocess, sys, shutil, logging
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Tables the merge will touch, in dependency order
MERGE_TABLES = [
    "jid", "chat", "message",
    "message_text", "message_media", "message_quoted",
    "message_link", "message_thumbnail",
    "message_vcard", "message_vcard_jid",
    "message_mentions",
    "message_system", "message_system_chat_participant", "message_system_group",
    "receipt_user", "receipt_orphaned", "message_ephemeral",
]

# For each dependent table: which columns are FKs, and which remap dict to use
# remap keys: "jid", "chat", "msg"
FK_SPEC = {
    "message":                          {"chat_row_id": "chat", "sender_jid_row_id": "jid"},
    "message_text":                     {"message_row_id": "msg"},
    "message_media":                    {"message_row_id": "msg", "chat_row_id": "chat"},
    "message_quoted":                   {"message_row_id": "msg", "chat_row_id": "chat"},
    "message_link":                     {"message_row_id": "msg"},
    "message_thumbnail":                {"message_row_id": "msg"},
    "message_vcard":                    {"message_row_id": "msg"},
    "message_vcard_jid":                {"message_row_id": "msg", "vcard_jid_row_id": "jid"},
    "message_mentions":                 {"message_row_id": "msg", "jid_row_id": "jid"},
    "message_system":                   {"message_row_id": "msg"},
    "message_system_chat_participant":  {"message_row_id": "msg", "jid_row_id": "jid"},
    "message_system_group":             {"message_row_id": "msg"},
    "receipt_user":                     {"message_row_id": "msg", "receipt_user_jid_row_id": "jid"},
    "receipt_orphaned":                 {"message_row_id": "msg"},
    "message_ephemeral":                {"message_row_id": "msg"},
}

# Chat FK columns that point at messages not yet merged — null them out initially
CHAT_DEFER_COLS = {
    "display_message_row_id", "last_read_message_row_id",
    "last_message_row_id", "last_notified_message_row_id",
    "last_read_receipt_sent_message_row_id",
}

PK_BUMP = 1_000_000


# ─── helpers ──────────────────────────────────────────────────────────────────

def _ts(ms):
    if ms is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ms)


def _tables(con, db="main"):
    q = f"SELECT name FROM {db}.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    return {r[0] for r in con.execute(q)}


def _cols(con, table, db="main"):
    return [r[1] for r in con.execute(f"PRAGMA {db}.table_info({table})")]


def _pk_offset(con, table):
    try:
        v = con.execute(f"SELECT COALESCE(MAX(_id), 0) FROM main.{table}").fetchone()[0]
        return int(v) + PK_BUMP
    except Exception:
        return PK_BUMP


# ─── Phase 1: decrypt ─────────────────────────────────────────────────────────

def phase1_decrypt(old_crypt, old_key, new_crypt, new_key, work_dir, emit):
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    old_db = work_dir / "old_msgstore.db"
    new_db = work_dir / "new_msgstore.db"

    emit("phase1", 5,  "Decrypting old backup…")
    _wadecrypt(old_key, old_crypt, old_db)
    emit("phase1", 42, f"Old decrypted — {old_db.stat().st_size:,} bytes")

    emit("phase1", 48, "Decrypting new backup…")
    _wadecrypt(new_key, new_crypt, new_db)
    emit("phase1", 85, f"New decrypted — {new_db.stat().st_size:,} bytes")

    emit("phase1", 90, "Running PRAGMA integrity_check on both…")
    result = {"old": _db_stats(old_db), "new": _db_stats(new_db)}

    emit("phase1", 100, "Phase 1 complete")
    return result


def _wadecrypt(key, crypt, out):
    r = subprocess.run(
        [sys.executable, "-m", "wa_crypt_tools.wadecrypt",
         str(key), str(crypt), str(out)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not out.exists():
        raise RuntimeError(f"wadecrypt failed:\n{r.stderr}\n{r.stdout}")


def _db_stats(path):
    path = Path(path)
    con = sqlite3.connect(str(path))
    try:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        version   = con.execute("PRAGMA user_version").fetchone()[0]
        tbls      = _tables(con)
        msgs = chats = ts_min = ts_max = 0
        if "message" in tbls:
            r = con.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM message").fetchone()
            msgs, ts_min, ts_max = r
        if "chat" in tbls:
            chats = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
        return {
            "size":         path.stat().st_size,
            "integrity":    integrity,
            "user_version": version,
            "messages":     msgs  or 0,
            "chats":        chats or 0,
            "date_min":     _ts(ts_min),
            "date_max":     _ts(ts_max),
        }
    finally:
        con.close()


# ─── Phase 2: schema diff ─────────────────────────────────────────────────────

def phase2_schema(work_dir, emit):
    work_dir = Path(work_dir)
    emit("phase2", 10, "Loading table lists…")

    old_con = sqlite3.connect(str(work_dir / "old_msgstore.db"))
    new_con = sqlite3.connect(str(work_dir / "new_msgstore.db"))

    old_tbls = _tables(old_con)
    new_tbls = _tables(new_con)

    only_old = sorted(old_tbls - new_tbls)
    only_new = sorted(new_tbls - old_tbls)
    shared   = old_tbls & new_tbls

    emit("phase2", 40, f"Shared: {len(shared)} | Only-old: {len(only_old)} | Only-new: {len(only_new)}")

    col_diffs = {}
    for tbl in sorted(shared):
        oc = {r[1]: r[2] for r in old_con.execute(f"PRAGMA table_info({tbl})")}
        nc = {r[1]: r[2] for r in new_con.execute(f"PRAGMA table_info({tbl})")}
        added   = {k: nc[k] for k in nc if k not in oc}
        removed = {k: oc[k] for k in oc if k not in nc}
        changed = {k: (oc[k], nc[k]) for k in oc if k in nc and oc[k] != nc[k]}
        if added or removed or changed:
            col_diffs[tbl] = {"added": added, "removed": removed, "type_changed": changed}

    old_con.close()
    new_con.close()

    mergeable = [t for t in MERGE_TABLES if t in old_tbls and t in new_tbls]
    skipped   = [t for t in MERGE_TABLES if t not in old_tbls or t not in new_tbls]

    emit("phase2", 100,
         f"Schema diff done — {len(col_diffs)} tables with column changes, {len(mergeable)} tables to merge")

    return {
        "only_old":   only_old,
        "only_new":   only_new,
        "col_diffs":  col_diffs,
        "mergeable":  mergeable,
        "skipped":    skipped,
    }


# ─── Phase 3: merge ───────────────────────────────────────────────────────────

def phase3_merge(work_dir, emit):
    work_dir  = Path(work_dir)
    old_db    = work_dir / "old_msgstore.db"
    new_db    = work_dir / "new_msgstore.db"
    merged_db = work_dir / "merged.db"

    emit("phase3", 2, "Copying new DB as merge base…")
    shutil.copy2(str(new_db), str(merged_db))

    con = sqlite3.connect(str(merged_db))
    con.execute("PRAGMA foreign_keys = OFF")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA synchronous = NORMAL")
    # Attach old DB read-only
    con.execute(f"ATTACH DATABASE 'file:{old_db.as_posix()}?mode=ro' AS old")

    new_tbls = _tables(con, "main")
    old_tbls = _tables(con, "old")
    mergeable = [t for t in MERGE_TABLES if t in new_tbls and t in old_tbls]

    offsets = {t: _pk_offset(con, t) for t in mergeable}
    remap   = {"jid": {}, "chat": {}, "msg": {}}

    con.execute("BEGIN")
    try:
        # 1. jid — deduplicate by raw_string
        if "jid" in mergeable:
            emit("phase3", 6, "Merging jid table…")
            remap["jid"] = _merge_jid(con, offsets["jid"])
            emit("phase3", 14, f"  jid: {len(remap['jid'])} old entries remapped")

        # 2. chat — deduplicate by resolved jid_row_id
        if "chat" in mergeable:
            emit("phase3", 16, "Merging chat table…")
            remap["chat"] = _merge_chat(con, offsets["chat"], remap["jid"])
            emit("phase3", 24, f"  chat: {len(remap['chat'])} old chats remapped")

        # 3. message — heaviest table
        if "message" in mergeable:
            emit("phase3", 26, "Merging message table (largest step)…")
            remap["msg"] = _merge_generic(
                con, "message", offsets["message"], remap,
                emit=emit, pct_start=26, pct_end=65,
            )
            emit("phase3", 65, f"  message: {len(remap['msg']):,} old rows merged")

        # 4. all dependent tables
        dep = [t for t in mergeable if t not in ("jid", "chat", "message")]
        for i, tbl in enumerate(dep):
            pct = 65 + int(i / max(len(dep), 1) * 20)
            emit("phase3", pct, f"Merging {tbl}…")
            _merge_generic(con, tbl, offsets.get(tbl, PK_BUMP), remap)

        emit("phase3", 86, "Committing transaction…")
        con.execute("COMMIT")

        emit("phase3", 88, "Rebuilding FTS indexes…")
        _rebuild_fts(con)

        emit("phase3", 91, "Running integrity_check…")
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.execute("PRAGMA foreign_keys = ON")
        fk_bad = len(con.execute("PRAGMA foreign_key_check").fetchall())
        if fk_bad:
            emit("phase3", 92, f"  {fk_bad} FK violations detected (WhatsApp tolerates these)")

        emit("phase3", 94, "VACUUM…")
        con.execute("VACUUM")

        emit("phase3", 98, "Computing statistics…")
        stats = _gate3_stats(con)
        stats["integrity"]    = integrity
        stats["fk_violations"] = fk_bad
        emit("phase3", 100, f"Merge complete — {stats['total_messages']:,} total messages")
        return stats

    except Exception:
        try:
            con.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        con.close()


def _merge_jid(con, offset):
    existing = {r[0]: r[1] for r in con.execute("SELECT raw_string, _id FROM main.jid")}
    remap = {}

    old_c  = _cols(con, "jid", "old")
    new_c  = _cols(con, "jid", "main")
    common = [c for c in old_c if c in new_c]
    ph     = ",".join("?" * len(common))

    for row in con.execute(f"SELECT {','.join(common)} FROM old.jid"):
        d   = dict(zip(common, row))
        oid = d["_id"]
        rs  = d.get("raw_string", "")

        if rs in existing:
            remap[oid] = existing[rs]
        else:
            nid        = oid + offset
            d["_id"]   = nid
            con.execute(
                f"INSERT OR IGNORE INTO main.jid({','.join(d)}) VALUES({ph})",
                list(d.values()),
            )
            remap[oid]   = nid
            existing[rs] = nid

    return remap


def _merge_chat(con, offset, jid_remap):
    existing = {r[0]: r[1] for r in con.execute("SELECT jid_row_id, _id FROM main.chat")}
    remap = {}

    old_c  = _cols(con, "chat", "old")
    new_c  = _cols(con, "chat", "main")
    common = [c for c in old_c if c in new_c]
    ph     = ",".join("?" * len(common))

    for row in con.execute(f"SELECT {','.join(common)} FROM old.chat"):
        d   = dict(zip(common, row))
        oid = d["_id"]

        if "jid_row_id" in d and d["jid_row_id"] is not None:
            d["jid_row_id"] = jid_remap.get(d["jid_row_id"], d["jid_row_id"] + offset)

        resolved_jid = d.get("jid_row_id")
        if resolved_jid in existing:
            remap[oid] = existing[resolved_jid]
            continue

        nid      = oid + offset
        d["_id"] = nid

        for col in CHAT_DEFER_COLS:
            if col in d:
                d[col] = None

        try:
            con.execute(
                f"INSERT OR IGNORE INTO main.chat({','.join(d)}) VALUES({ph})",
                list(d.values()),
            )
            remap[oid] = nid
            if resolved_jid is not None:
                existing[resolved_jid] = nid
        except sqlite3.Error:
            remap[oid] = nid

    return remap


def _merge_generic(con, tbl, offset, remap, emit=None, pct_start=0, pct_end=100):
    old_c  = _cols(con, tbl, "old")
    new_c  = _cols(con, tbl, "main")
    common = [c for c in old_c if c in new_c]
    if not common:
        return {}

    ph       = ",".join("?" * len(common))
    fk_spec  = FK_SPEC.get(tbl, {})
    tbl_remap = {}

    total = 0
    if emit:
        try:
            total = con.execute(f"SELECT COUNT(*) FROM old.{tbl}").fetchone()[0]
        except Exception:
            pass
    done = 0

    for row in con.execute(f"SELECT {','.join(common)} FROM old.{tbl}"):
        d   = dict(zip(common, row))
        oid = d.get("_id")

        if "_id" in d:
            d["_id"] = oid + offset

        skip = False
        for col, rkey in fk_spec.items():
            if col in d and d[col] is not None:
                old_val = d[col]
                new_val = remap[rkey].get(old_val)
                if new_val is None:
                    skip = True
                    break
                d[col] = new_val

        if not skip:
            try:
                con.execute(
                    f"INSERT OR IGNORE INTO main.{tbl}({','.join(d)}) VALUES({ph})",
                    list(d.values()),
                )
                if oid is not None:
                    tbl_remap[oid] = d.get("_id", oid + offset)
            except sqlite3.Error:
                pass

        done += 1
        if emit and total and done % 10_000 == 0:
            pct = pct_start + int(done / total * (pct_end - pct_start))
            emit("phase3", min(pct, pct_end - 1), f"  {tbl}: {done:,}/{total:,}")

    return tbl_remap


def _rebuild_fts(con):
    skip_suffixes = ("_content", "_segdir", "_segments", "_stat",
                     "_docsize", "_data", "_idx", "_config")
    fts_tbls = [
        r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name LIKE '%fts%' OR name LIKE '%search%')"
        )
        if not any(r[0].endswith(s) for s in skip_suffixes)
    ]
    for fts in fts_tbls:
        for cmd in ("rebuild", "integrity-check"):
            try:
                con.execute(f"INSERT INTO {fts}({fts}) VALUES(?)", (cmd,))
                break
            except sqlite3.Error:
                pass


def _gate3_stats(con):
    total = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
    chats = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
    ts_min, ts_max = con.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM message"
    ).fetchone()

    per_year = {}
    for yr, cnt in con.execute("""
        SELECT CAST(strftime('%Y', datetime(timestamp/1000,'unixepoch')) AS INTEGER),
               COUNT(*)
        FROM message
        WHERE timestamp IS NOT NULL
        GROUP BY 1 ORDER BY 1
    """):
        per_year[int(yr)] = cnt

    return {
        "total_messages": total,
        "total_chats":    chats,
        "date_min":       _ts(ts_min),
        "date_max":       _ts(ts_max),
        "per_year":       per_year,
    }


# ─── Phase 4: re-encrypt ──────────────────────────────────────────────────────

def phase4_encrypt(new_crypt, new_key, work_dir, output_dir, emit):
    work_dir   = Path(work_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    merged_db = work_dir / "merged.db"
    out_crypt  = output_dir / "msgstore.db.crypt15"

    emit("phase4", 20, "Re-encrypting merged database…")
    r = subprocess.run(
        [sys.executable, "-m", "wa_crypt_tools.waencrypt",
         "--reference", str(new_crypt),
         str(new_key), str(merged_db), str(out_crypt)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not out_crypt.exists():
        raise RuntimeError(f"waencrypt failed:\n{r.stderr}\n{r.stdout}")

    size = out_crypt.stat().st_size
    emit("phase4", 100, f"Output written — {size:,} bytes")
    return {"path": str(out_crypt), "size": size}
