"""
WhatsApp crypt15 merge pipeline — Phases 1-6.
Called from app.py; progress is delivered via emit(phase, pct, msg).
"""
import sqlite3, subprocess, sys, shutil, csv, logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

MERGE_TABLES = [
    "jid", "chat", "message",
    "message_text", "message_media", "message_quoted",
    "message_link", "message_thumbnail",
    "message_vcard", "message_vcard_jid",
    "message_mentions",
    "message_system", "message_system_chat_participant", "message_system_group",
    "receipt_user", "receipt_orphaned", "message_ephemeral",
]

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

CHAT_DEFER_COLS = {
    "display_message_row_id", "last_read_message_row_id",
    "last_message_row_id", "last_notified_message_row_id",
    "last_read_receipt_sent_message_row_id",
}

PK_BUMP = 1_000_000


# ── helpers ───────────────────────────────────────────────────────────────────

def _ts(ms):
    if ms is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ms)


def _fmt_size(b):
    b = int(b or 0)
    if b >= 1_000_000_000:
        return f"{b/1e9:.1f} GB"
    if b >= 1_000_000:
        return f"{b/1e6:.1f} MB"
    if b >= 1_000:
        return f"{b/1e3:.0f} KB"
    return f"{b} B"


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


def _prep_key(key_source, work_dir):
    """
    Accept a binary key file (32 bytes) OR a text file with a 64-char hex string.
    Returns path to a binary key file, writing a temp one if the input was hex.
    """
    src = Path(str(key_source))
    if not src.exists():
        raise FileNotFoundError(f"Key file not found: {src}")

    data = src.read_bytes()

    # Already binary
    if len(data) == 32:
        return src

    # Try hex text
    text = data.decode("utf-8", errors="ignore").strip()
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        tmp = Path(work_dir) / (src.stem + "_bin.key")
        tmp.write_bytes(bytes.fromhex(text))
        return tmp

    raise ValueError(
        f"Unrecognised key format in {src.name}: "
        f"{len(data)} bytes (expected 32-byte binary or 64-char hex text)"
    )


# ── Phase 1: decrypt ──────────────────────────────────────────────────────────

def phase1_decrypt(old_crypt, old_key, new_crypt, new_key, work_dir, emit):
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    old_db = work_dir / "old_msgstore.db"
    new_db = work_dir / "new_msgstore.db"

    emit("phase1", 5, "Preparing keys...")
    old_key_bin = _prep_key(old_key, work_dir)
    new_key_bin = _prep_key(new_key, work_dir)

    emit("phase1", 10, "Decrypting old backup...")
    _wadecrypt(old_key_bin, old_crypt, old_db)
    emit("phase1", 45, f"Old decrypted — {old_db.stat().st_size:,} bytes")

    emit("phase1", 50, "Decrypting new backup...")
    _wadecrypt(new_key_bin, new_crypt, new_db)
    emit("phase1", 85, f"New decrypted — {new_db.stat().st_size:,} bytes")

    emit("phase1", 90, "Running PRAGMA integrity_check on both...")
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
            r = con.execute(
                "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM message"
            ).fetchone()
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


# ── Phase 2: schema diff ──────────────────────────────────────────────────────

def phase2_schema(work_dir, emit):
    work_dir = Path(work_dir)
    emit("phase2", 10, "Loading table lists...")

    old_con = sqlite3.connect(str(work_dir / "old_msgstore.db"))
    new_con = sqlite3.connect(str(work_dir / "new_msgstore.db"))

    old_tbls = _tables(old_con)
    new_tbls = _tables(new_con)
    only_old = sorted(old_tbls - new_tbls)
    only_new = sorted(new_tbls - old_tbls)
    shared   = old_tbls & new_tbls

    emit("phase2", 40,
         f"Shared: {len(shared)} | Only-old: {len(only_old)} | Only-new: {len(only_new)}")

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
         f"Schema diff done — {len(col_diffs)} tables differ, {len(mergeable)} mergeable")

    return {
        "only_old":  only_old,
        "only_new":  only_new,
        "col_diffs": col_diffs,
        "mergeable": mergeable,
        "skipped":   skipped,
    }


# ── Phase 3: merge ────────────────────────────────────────────────────────────

def phase3_merge(work_dir, emit):
    work_dir  = Path(work_dir)
    old_db    = work_dir / "old_msgstore.db"
    new_db    = work_dir / "new_msgstore.db"
    merged_db = work_dir / "merged.db"

    emit("phase3", 2, "Copying new DB as merge base...")
    shutil.copy2(str(new_db), str(merged_db))

    con = sqlite3.connect(str(merged_db))
    con.execute("PRAGMA foreign_keys = OFF")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA synchronous = NORMAL")
    con.execute("ATTACH DATABASE ? AS old", (str(old_db.resolve()),))

    new_tbls  = _tables(con, "main")
    old_tbls  = _tables(con, "old")
    mergeable = [t for t in MERGE_TABLES if t in new_tbls and t in old_tbls]
    offsets   = {t: _pk_offset(con, t) for t in mergeable}
    remap     = {"jid": {}, "chat": {}, "msg": {}}

    con.execute("BEGIN")
    try:
        if "jid" in mergeable:
            emit("phase3", 6, "Merging jid...")
            remap["jid"] = _merge_jid(con, offsets["jid"])
            emit("phase3", 14, f"  jid: {len(remap['jid'])} entries remapped")

        if "chat" in mergeable:
            emit("phase3", 16, "Merging chat...")
            remap["chat"] = _merge_chat(con, offsets["chat"], remap["jid"])
            emit("phase3", 24, f"  chat: {len(remap['chat'])} chats remapped")

        if "message" in mergeable:
            emit("phase3", 26, "Merging message table (largest step)...")
            remap["msg"] = _merge_generic(
                con, "message", offsets["message"], remap,
                emit=emit, pct_start=26, pct_end=65,
            )
            emit("phase3", 65, f"  message: {len(remap['msg']):,} rows merged")

        dep = [t for t in mergeable if t not in ("jid", "chat", "message")]
        for i, tbl in enumerate(dep):
            pct = 65 + int(i / max(len(dep), 1) * 20)
            emit("phase3", pct, f"Merging {tbl}...")
            _merge_generic(con, tbl, offsets.get(tbl, PK_BUMP), remap)

        emit("phase3", 86, "Committing...")
        con.execute("COMMIT")

        emit("phase3", 88, "Rebuilding FTS indexes...")
        _rebuild_fts(con)

        emit("phase3", 91, "Integrity check...")
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.execute("PRAGMA foreign_keys = ON")
        fk_bad = len(con.execute("PRAGMA foreign_key_check").fetchall())
        if fk_bad:
            emit("phase3", 92, f"  {fk_bad} FK violations (WhatsApp tolerates these)")

        emit("phase3", 94, "VACUUM...")
        con.isolation_level = None
        con.execute("VACUUM")
        con.isolation_level = ""

        emit("phase3", 98, "Computing statistics...")
        stats = _gate3_stats(con)
        stats["integrity"]      = integrity
        stats["fk_violations"]  = fk_bad
        stats["old_msg_offset"] = offsets.get("message", PK_BUMP)

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
            nid = oid + offset
            d["_id"] = nid
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
    ph        = ",".join("?" * len(common))
    fk_spec   = FK_SPEC.get(tbl, {})
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
                new_val = remap[rkey].get(d[col])
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
    skip = ("_content", "_segdir", "_segments", "_stat",
            "_docsize", "_data", "_idx", "_config")
    tbls = [
        r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name LIKE '%fts%' OR name LIKE '%search%')"
        )
        if not any(r[0].endswith(s) for s in skip)
    ]
    for fts in tbls:
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
        FROM message WHERE timestamp IS NOT NULL
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


# ── Phase 4: re-encrypt ───────────────────────────────────────────────────────

def phase4_encrypt(new_crypt, new_key, work_dir, output_dir, emit):
    work_dir   = Path(work_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    new_key_bin = _prep_key(new_key, work_dir)
    merged_db   = work_dir / "merged.db"
    out_crypt   = output_dir / "msgstore.db.crypt15"

    emit("phase4", 20, "Re-encrypting merged database...")
    r = subprocess.run(
        [sys.executable, "-m", "wa_crypt_tools.waencrypt",
         "--reference", str(new_crypt),
         str(new_key_bin), str(merged_db), str(out_crypt)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not out_crypt.exists():
        raise RuntimeError(f"waencrypt failed:\n{r.stderr}\n{r.stdout}")

    size = out_crypt.stat().st_size
    emit("phase4", 100, f"Output written — {_fmt_size(size)}")
    return {"path": str(out_crypt), "size": size}


# ── Phase 5: media reconciliation ─────────────────────────────────────────────

def phase5_media(work_dir, old_media_dir, output_dir, emit, old_msg_offset=PK_BUMP):
    work_dir   = Path(work_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    merged_db = work_dir / "merged.db"
    if not merged_db.exists():
        raise RuntimeError("merged.db not found — run Phase 3 first")

    emit("phase5", 8, "Querying media rows from merged DB...")
    con = sqlite3.connect(str(merged_db))

    # All media rows, flagged as old/new origin
    rows = con.execute("""
        SELECT
            mm._id,
            mm.file_path,
            COALESCE(mm.file_size, 0)  AS file_size,
            COALESCE(mm.mime_type, '') AS mime_type,
            COALESCE(j.raw_string, 'unknown') AS chat_jid,
            CASE WHEN mm._id >= ? THEN 'old' ELSE 'new' END AS origin
        FROM message_media mm
        LEFT JOIN chat c ON c._id = mm.chat_row_id
        LEFT JOIN jid  j ON j._id = c.jid_row_id
        ORDER BY mm.file_path
    """, (old_msg_offset,)).fetchall()
    con.close()

    old_rows = [r for r in rows if r[5] == "old"]
    emit("phase5", 25, f"Found {len(old_rows):,} old-origin media files ({len(rows):,} total)")

    # Write manifest CSV
    csv_path = output_dir / "media_manifest.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file_path", "size_bytes", "mime_type", "chat", "origin"])
        for _, path, size, mime, chat, origin in rows:
            w.writerow([path, size, mime, chat, origin])
    emit("phase5", 45, f"media_manifest.csv written ({len(rows):,} rows)")

    # Group old-origin files by top-level media folder
    folders = defaultdict(lambda: {"count": 0, "size": 0})
    for _, path, size, mime, chat, _ in old_rows:
        folder = (path or "").replace("\\", "/").split("/")[0] or "Unknown"
        folders[folder]["count"] += 1
        folders[folder]["size"]  += int(size or 0)

    total_size = sum(d["size"] for d in folders.values())

    # Optional cross-check
    coverage = missing_count = found_count = None
    if old_media_dir:
        omdir = Path(old_media_dir)
        if omdir.exists():
            emit("phase5", 55, f"Cross-checking against {omdir}...")
            found = missing = 0
            for _, path, *_ in old_rows:
                if not path:
                    continue
                rel  = path.replace("\\", "/").lstrip("/")
                full = omdir / rel
                if full.exists():
                    found += 1
                else:
                    missing += 1
            total_check   = found + missing
            coverage      = round(found / total_check * 100, 1) if total_check else 0
            missing_count = missing
            found_count   = found
            emit("phase5", 72,
                 f"Coverage: {coverage}% ({found:,}/{total_check:,} files on disk)")
        else:
            emit("phase5", 72, f"old_media path not found — skipping file check")

    # Write markdown summary
    md_lines = [
        "# Media Migration Summary",
        "",
        f"Source: `merged.db` · {len(old_rows):,} media files migrated from old backup",
        f"({len(rows):,} total across both backups)",
        "",
        "## Files by Folder (old backup only)",
        "",
        "| Folder | Files | Size |",
        "|--------|------:|-----:|",
    ]
    for folder, data in sorted(folders.items(), key=lambda x: -x[1]["size"]):
        md_lines.append(f"| {folder} | {data['count']:,} | {_fmt_size(data['size'])} |")
    md_lines += [
        "",
        f"**Total old-backup media: {len(old_rows):,} files · {_fmt_size(total_size)}**",
        "",
    ]
    if coverage is not None:
        status = "OK" if coverage >= 95 else "WARNING"
        md_lines += [
            "## File Coverage Check",
            "",
            f"- Files found on disk: **{coverage}%** [{status}]",
            f"- Found: {found_count:,}",
            f"- Missing: {missing_count:,}",
            "",
        ]
    md_lines += [
        "## How to Transfer Media",
        "",
        "Connect the **old phone** via USB (File Transfer mode) and copy:",
        "",
        "```",
        "FROM  old phone:  Android/media/com.whatsapp/WhatsApp/Media/",
        "TO    new phone:  Android/media/com.whatsapp/WhatsApp/Media/",
        "```",
        "",
        "> Merge folders — do NOT replace. Skip duplicates.",
        "> Do this **BEFORE** restoring the backup file.",
    ]

    md_path = output_dir / "media_summary.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    emit("phase5", 100, "Phase 5 complete")

    return {
        "total_media":   len(rows),
        "old_media":     len(old_rows),
        "total_size":    total_size,
        "folders":       dict(folders),
        "coverage":      coverage,
        "missing":       missing_count,
    }


# ── Phase 6: restore playbook ─────────────────────────────────────────────────

def phase6_playbook(output_dir, gates, emit):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    g3 = gates.get(3, {})
    g4 = gates.get(4, {})
    g5 = gates.get(5, {})

    lines = [
        "# WhatsApp Backup Restore Playbook",
        "",
        f"*Generated by WhatsApp Backup Merger*",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Total messages | **{g3.get('total_messages', 'N/A'):,}** |",
        f"| Date range | {g3.get('date_min', 'N/A')} to {g3.get('date_max', 'N/A')} |",
        f"| Chats | {g3.get('total_chats', 'N/A')} |",
        f"| Output file | `msgstore.db.crypt15` ({_fmt_size(g4.get('size', 0))}) |",
        f"| Media files to transfer | {g5.get('old_media', 'see media_summary.md'):,} files |",
        "",
        "---",
        "",
        "## Step 1 — Safety Backup (rollback point)",
        "",
        "On your **new phone**:",
        "1. Open WhatsApp",
        "2. Settings → Chats → Chat Backup → **Back Up Now**",
        "3. Wait for it to complete and note the timestamp shown",
        "",
        "---",
        "",
        "## Step 2 — Transfer Media Files",
        "",
        "> **Do this before placing the backup file.** WhatsApp needs the media",
        "> present when it first loads the restored messages.",
        "",
        "Connect your **old phone** via USB in File Transfer mode:",
        "",
        "```",
        "Copy FROM old phone:",
        "  Android/media/com.whatsapp/WhatsApp/Media/",
        "",
        "Paste TO new phone (exact same path):",
        "  Android/media/com.whatsapp/WhatsApp/Media/",
        "```",
        "",
        "- Select **Merge** when prompted, not Replace",
        "- Skip duplicate files",
        f"- See `media_summary.md` for the full file list and sizes",
        "",
        "---",
        "",
        "## Step 3 — Place the Merged Backup File",
        "",
        "Copy **`output/msgstore.db.crypt15`** to your new phone:",
        "",
        "**Android 11 and newer:**",
        "```",
        "Android/media/com.whatsapp/WhatsApp/Backups/msgstore.db.crypt15",
        "```",
        "",
        "**Android 10 and older:**",
        "```",
        "WhatsApp/Databases/msgstore.db.crypt15",
        "```",
        "",
        "> Replace the existing file. Keep a copy of the original as a backup.",
        "",
        "---",
        "",
        "## Step 4 — Restore",
        "",
        "1. **Uninstall WhatsApp** completely (full uninstall, not just clear data)",
        "2. **Reinstall** from the Play Store",
        "3. Enter your **same phone number** and verify it",
        "4. When prompted to restore, choose **Restore from local backup**",
        "   *(not Google Drive — the merged file is local only)*",
        "5. Enter your **new phone's 64-digit backup encryption key** when prompted",
        "   *(Settings → Chats → Chat Backup → Backup encryption key)*",
        "6. Wait for the restore to finish",
        "",
        "---",
        "",
        "## Troubleshooting",
        "",
        "### 'Invalid backup key'",
        "- Make sure you typed the key for the **new** phone, not the old one",
        "- Re-run Phase 4 and confirm `--reference` points to `new_msgstore.db.crypt15`",
        "- If it still fails, try re-encrypting with explicit feature flags:",
        "  ```",
        "  waencrypt --reference new_msgstore.db.crypt15 [NEW_KEY] \\",
        "            work/merged.db output/msgstore.db.crypt15",
        "  ```",
        "",
        "### 'Backup is corrupt' or restore refused",
        "- Your installed WhatsApp version may be newer than the backup was written for",
        "- Workaround: update WhatsApp **before** uninstalling, then try again",
        "- Fallback: your original backups are untouched; use",
        "  [whatsapp-viewer](https://github.com/andreas-mausch/whatsapp-viewer) to",
        "  read `work/merged.db` directly as a permanent archive",
        "",
        "### Old messages missing",
        "- Check the per-year counts in Gate 3 against expectations",
        "- Group chats may show fewer messages if participant JIDs were not in either backup",
        "",
        "### Media shows as 'unavailable'",
        "- Confirm Step 2 was completed **before** Step 4",
        "- Check that `media_manifest.csv` file paths match the folder structure on the new phone",
        "",
        "---",
        "",
        "## Step 5 — Verification Checklist",
        "",
        "After restore completes:",
        "",
        "- [ ] Open the oldest chat — 2015 messages render correctly",
        "- [ ] Open a recent 2026 chat — messages are present",
        "- [ ] Tap an old photo (e.g. from 2018) — it opens without 'unavailable' banner",
        "- [ ] Use Search — returns results from both 2015 and 2026",
        "- [ ] Open a group chat — member names display correctly",
        "",
        "---",
        "",
        "*All five checks passing = successful merge. You now have your full 11-year history.*",
    ]

    playbook_path = output_dir / "restore_playbook.md"
    playbook_path.write_text("\n".join(lines), encoding="utf-8")
    emit("phase6", 100, "restore_playbook.md written")
    return {"path": str(playbook_path)}


# ── Merge report ──────────────────────────────────────────────────────────────

def write_merge_report(output_dir, gates):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    g1 = gates.get(1, {})
    g2 = gates.get(2, {})
    g3 = gates.get(3, {})
    g4 = gates.get(4, {})
    g5 = gates.get(5, {})

    lines = [
        "# Merge Report",
        "",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        "",
        "---",
        "",
        "## Phase 1 — Decryption",
        "",
        "| | Old backup | New backup |",
        "|---|---|---|",
    ]
    for key, label in [
        ("size",         "File size"),
        ("integrity",    "Integrity"),
        ("user_version", "Schema version"),
        ("messages",     "Messages"),
        ("chats",        "Chats"),
        ("date_min",     "Earliest message"),
        ("date_max",     "Latest message"),
    ]:
        old_v = g1.get("old", {}).get(key, "N/A")
        new_v = g1.get("new", {}).get(key, "N/A")
        if key == "size":
            old_v = _fmt_size(old_v) if old_v != "N/A" else "N/A"
            new_v = _fmt_size(new_v) if new_v != "N/A" else "N/A"
        lines.append(f"| {label} | {old_v} | {new_v} |")

    lines += [
        "",
        "## Phase 2 — Schema",
        "",
        f"- Mergeable tables: {len(g2.get('mergeable', []))}",
        f"- New-only tables: {len(g2.get('only_new', []))}",
        f"- Old-only tables: {len(g2.get('only_old', []))}",
        f"- Tables with column changes: {len(g2.get('col_diffs', {}))}",
        "",
        "## Phase 3 — Merge",
        "",
        f"- Total messages: **{g3.get('total_messages', 'N/A'):,}**",
        f"- Total chats: {g3.get('total_chats', 'N/A')}",
        f"- Date range: {g3.get('date_min', 'N/A')} to {g3.get('date_max', 'N/A')}",
        f"- Integrity check: {g3.get('integrity', 'N/A')}",
        f"- FK violations: {g3.get('fk_violations', 0)}",
        "",
        "### Messages per year",
        "",
        "| Year | Count |",
        "|------|------:|",
    ]
    for yr, cnt in sorted((g3.get("per_year") or {}).items()):
        lines.append(f"| {yr} | {cnt:,} |")

    lines += [
        "",
        "## Phase 4 — Re-encryption",
        "",
        f"- Output: `output/msgstore.db.crypt15`",
        f"- Size: {_fmt_size(g4.get('size', 0))}",
        f"- Command: `waencrypt --reference new_msgstore.db.crypt15 [NEW_KEY] work/merged.db output/msgstore.db.crypt15`",
        "",
        "## Phase 5 — Media",
        "",
        f"- Old-backup media files: {g5.get('old_media', 'N/A'):,}",
        f"- Total size: {_fmt_size(g5.get('total_size', 0))}",
    ]
    if g5.get("coverage") is not None:
        lines.append(f"- File coverage: {g5['coverage']}%")

    lines += [
        "",
        "---",
        "",
        "*Keys were not logged. Input files were not modified.*",
    ]

    report_path = output_dir / "merge_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return str(report_path)
