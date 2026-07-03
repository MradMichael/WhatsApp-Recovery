"""
WhatsApp crypt15 backup merger — v3
PRIVACY: hex keys are read into memory and NEVER printed, echoed, logged,
         or written anywhere except as ephemeral binary temp files.

Usage:
  python output/merge.py phase1   # Decrypt + integrity check  → GATE 1
  python output/merge.py phase2   # Schema reconciliation      → GATE 2
  python output/merge.py phase3   # FK remapping + merge       → GATE 3
  python output/merge.py phase4   # Verify merged DB           → GATE 4
  python output/merge.py phase5   # Media manifest             → GATE 5
  python output/merge.py phase6   # Re-encrypt + RESTORE.md   → GATE 6

Expected layout:
  ./old-phone/msgstore.db.crypt15   ./old-phone/key.txt  (64-char hex)
  ./new-phone/msgstore.db.crypt15   ./new-phone/key.txt  (64-char hex)
  ./output/   (all output goes here; this script lives here)
"""
import sys, re, csv, json, shutil, sqlite3, subprocess, tempfile, textwrap
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

# ── Paths ──────────────────────────────────────────────────────────────────────
OUT_DIR      = Path(__file__).parent.resolve()   # ./output/
ROOT         = OUT_DIR.parent                    # project root

OLD_DIR      = ROOT / "old-phone"
NEW_DIR      = ROOT / "new-phone"
OLD_CRYPT    = OLD_DIR / "msgstore.db.crypt15"
NEW_CRYPT    = NEW_DIR / "msgstore.db.crypt15"
OLD_KEY_F    = OLD_DIR / "key.txt"
NEW_KEY_F    = NEW_DIR / "key.txt"
OLD_DB       = OUT_DIR / "old_msgstore.db"
NEW_DB       = OUT_DIR / "new_msgstore.db"
MERGED_DB    = OUT_DIR / "merged.db"
MERGED_CRYPT = OUT_DIR / "msgstore.db.crypt15"
REPORT       = OUT_DIR / "merge_report.md"
MEDIA_CSV    = OUT_DIR / "media_manifest.csv"
RESTORE_MD   = OUT_DIR / "RESTORE.md"
VENV_DIR     = ROOT / "venv"

# ── Utilities ──────────────────────────────────────────────────────────────────

def ts(ms):
    """ms epoch → YYYY-MM-DD (UTC). Handles both ms and second timestamps."""
    if not ms:
        return "N/A"
    try:
        # Heuristic: values > 1e11 are ms; others are seconds
        epoch_s = ms / 1000 if ms > 1e11 else ms
        return datetime.fromtimestamp(epoch_s, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "N/A"

def read_key(path: Path) -> str:
    """Read 64-char hex key from file. NEVER print or log the return value."""
    raw = path.read_text(encoding="utf-8").strip()
    if len(raw) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise ValueError(f"{path.name}: expected exactly 64 hex chars, got {len(raw)}")
    return raw

def _key_tmpfile(hex_key: str, tmpdir: str) -> Path:
    """Write 64-char hex as 32-byte binary to a temp file. Internal only."""
    p = Path(tmpdir) / "k.bin"
    p.write_bytes(bytes.fromhex(hex_key))
    return p

def venv_exe(name: str) -> Path:
    for candidate in [
        VENV_DIR / "Scripts" / (name + ".exe"),
        VENV_DIR / "Scripts" / name,
        VENV_DIR / "bin" / name,
    ]:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"'{name}' not found in venv. "
        f"Run: python -m venv venv && venv/Scripts/pip install wa-crypt-tools"
    )

def run_decrypt(hex_key: str, crypt_in: Path, db_out: Path):
    """Decrypt crypt15. hex_key is NEVER passed as a CLI argument."""
    exe = venv_exe("wadecrypt")
    with tempfile.TemporaryDirectory() as td:
        kf = _key_tmpfile(hex_key, td)
        r = subprocess.run(
            [str(exe), str(kf), str(crypt_in), str(db_out)],
            capture_output=True, text=True, timeout=180
        )
    if r.returncode != 0:
        raise RuntimeError(f"wadecrypt failed:\n{r.stderr[:800]}")

def run_encrypt(hex_key: str, reference: Path, db_in: Path, crypt_out: Path):
    """Re-encrypt merged DB. hex_key never in CLI args."""
    exe = venv_exe("waencrypt")
    with tempfile.TemporaryDirectory() as td:
        kf = _key_tmpfile(hex_key, td)
        r = subprocess.run(
            [str(exe), "--reference", str(reference),
             str(kf), str(db_in), str(crypt_out)],
            capture_output=True, text=True, timeout=300
        )
    if r.returncode != 0:
        raise RuntimeError(f"waencrypt failed:\n{r.stderr[:800]}")

def integrity_check(path: Path) -> str:
    con = sqlite3.connect(str(path))
    result = con.execute("PRAGMA integrity_check").fetchone()[0]
    con.close()
    return result

def tbl_list(con: sqlite3.Connection) -> list:
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()]

def tbl_info(con: sqlite3.Connection, table: str) -> list:
    return con.execute(f"PRAGMA table_info(`{table}`)").fetchall()

_FTS_SHADOW = re.compile(r"_(content|segments|segdir|stat|docsize|config|data|idx|rowid)$")
_SKIP = {"sqlite_sequence", "sqlite_stat1", "android_metadata"}

def is_skip(name: str) -> bool:
    return name in _SKIP or bool(_FTS_SHADOW.search(name))

def fts_roots(con: sqlite3.Connection) -> set:
    roots = set()
    for row in con.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table'"
    ).fetchall():
        if row[1] and "fts" in row[1].lower():
            # actual FTS virtual table (not a shadow)
            if not _FTS_SHADOW.search(row[0]):
                roots.add(row[0])
    return roots

# ── Report helpers ─────────────────────────────────────────────────────────────

def report_init():
    REPORT.write_text(
        "# WhatsApp Merge Report — v3\n\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "> Keys are referred to as OLD\\_KEY / NEW\\_KEY and are never written to this file.\n",
        encoding="utf-8",
    )

def report_append(section: str):
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write("\n\n---\n\n" + section.strip())

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — DECRYPT
# ══════════════════════════════════════════════════════════════════════════════

def phase1():
    print("=" * 62)
    print("  PHASE 1 — Decrypt")
    print("=" * 62)

    # Verify inputs
    missing = [f for f in [OLD_CRYPT, NEW_CRYPT, OLD_KEY_F, NEW_KEY_F] if not f.exists()]
    if missing:
        for f in missing:
            print(f"  MISSING: {f}")
        sys.exit("\nPlace your files in old-phone/ and new-phone/ then re-run.")

    # Read keys (NEVER print them)
    old_key = read_key(OLD_KEY_F)
    new_key = read_key(NEW_KEY_F)
    print("  [OK] OLD_KEY and NEW_KEY read — not printed.")

    # Decrypt
    for label, hex_key, crypt, out_db in [
        ("old", old_key, OLD_CRYPT, OLD_DB),
        ("new", new_key, NEW_CRYPT, NEW_DB),
    ]:
        if out_db.exists():
            print(f"  [SKIP] {out_db.name} already exists.")
        else:
            print(f"  Decrypting {label}-phone backup ...", end=" ", flush=True)
            run_decrypt(hex_key, crypt, out_db)
            print(f"OK  ({out_db.stat().st_size:,} bytes)")

    # Integrity
    print()
    old_ic = integrity_check(OLD_DB)
    new_ic = integrity_check(NEW_DB)
    print(f"  integrity_check  old : {old_ic}")
    print(f"  integrity_check  new : {new_ic}")
    if old_ic != "ok" or new_ic != "ok":
        sys.exit("ERROR: integrity check failed — cannot continue.")

    # Gate 1 stats
    report_init()
    print()
    gate_data = {}
    for label, db_path in [("old", OLD_DB), ("new", NEW_DB)]:
        con = sqlite3.connect(str(db_path))
        uv     = con.execute("PRAGMA user_version").fetchone()[0]
        msgs   = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
        chats  = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
        ts_lo  = con.execute("SELECT MIN(timestamp) FROM message").fetchone()[0]
        ts_hi  = con.execute("SELECT MAX(timestamp) FROM message").fetchone()[0]
        con.close()
        gate_data[label] = dict(
            size=db_path.stat().st_size,
            user_version=uv, messages=msgs, chats=chats,
            date_min=ts(ts_lo), date_max=ts(ts_hi),
        )

    for label, d in gate_data.items():
        print(f"  [{label.upper()} PHONE]")
        print(f"    File size    : {d['size']:,} bytes  ({d['size']/1024/1024:.1f} MB)")
        print(f"    user_version : {d['user_version']}")
        print(f"    Messages     : {d['messages']:,}")
        print(f"    Chats        : {d['chats']:,}")
        print(f"    Date range   : {d['date_min']}  →  {d['date_max']}")
        print()

    report_append(f"""## Gate 1 — Decryption

| | Old phone | New phone |
|---|---|---|
| File size | {gate_data['old']['size']:,} B | {gate_data['new']['size']:,} B |
| user_version | {gate_data['old']['user_version']} | {gate_data['new']['user_version']} |
| Messages | {gate_data['old']['messages']:,} | {gate_data['new']['messages']:,} |
| Chats | {gate_data['old']['chats']:,} | {gate_data['new']['chats']:,} |
| Date range | {gate_data['old']['date_min']} → {gate_data['old']['date_max']} | {gate_data['new']['date_min']} → {gate_data['new']['date_max']} |
| integrity_check | ok | ok |

Keys: OLD\\_KEY / NEW\\_KEY — not logged.""")
    print(f"  Report: {REPORT}")
    print()
    print("  ► GATE 1 — confirm old ≈ 2015–2024 and new ≈ 2025–2026,")
    print("    then run:  python output/merge.py phase2")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SCHEMA RECONCILIATION
# ══════════════════════════════════════════════════════════════════════════════

def phase2():
    print("=" * 62)
    print("  PHASE 2 — Schema reconciliation")
    print("=" * 62)

    for db in [OLD_DB, NEW_DB]:
        if not db.exists():
            sys.exit(f"ERROR: {db.name} not found. Run phase1 first.")

    old_con = sqlite3.connect(str(OLD_DB))
    new_con = sqlite3.connect(str(NEW_DB))

    old_tbls = set(tbl_list(old_con)) - _SKIP
    new_tbls = set(tbl_list(new_con)) - _SKIP
    old_fts  = fts_roots(old_con)
    new_fts  = fts_roots(new_con)
    old_skip = old_fts | {t for t in old_tbls if is_skip(t)}
    new_skip = new_fts | {t for t in new_tbls if is_skip(t)}

    only_old = sorted(old_tbls - new_tbls - old_skip)
    only_new = sorted(new_tbls - old_tbls - new_skip)
    both     = sorted(old_tbls & new_tbls)

    # Column-level diff for shared tables
    col_diffs = {}
    for tbl in both:
        if is_skip(tbl):
            continue
        old_cols = {r[1]: r[2] for r in tbl_info(old_con, tbl)}
        new_cols = {r[1]: r[2] for r in tbl_info(new_con, tbl)}
        added    = {k: v for k, v in new_cols.items() if k not in old_cols}
        removed  = {k: v for k, v in old_cols.items() if k not in new_cols}
        changed  = {k: (old_cols[k], new_cols[k]) for k in old_cols
                    if k in new_cols and old_cols[k] != new_cols[k]}
        if added or removed or changed:
            col_diffs[tbl] = {"added": added, "removed": removed, "changed": changed}

    old_con.close()
    new_con.close()

    # Print
    print(f"\n  Tables only in OLD  ({len(only_old)}): {only_old or ['none']}")
    print(f"  Tables only in NEW  ({len(only_new)}): {only_new or ['none']}")
    print(f"  Tables in BOTH      ({len(both)})")

    if col_diffs:
        print(f"\n  Column differences in {len(col_diffs)} shared tables:")
        for tbl, d in sorted(col_diffs.items()):
            print(f"\n    [{tbl}]")
            for col, typ in d["added"].items():
                print(f"      +  {col} ({typ})   ← new only; will backfill NULL")
            for col, typ in d["removed"].items():
                print(f"      -  {col} ({typ})   ← old only; will drop")
            for col, (ot, nt) in d["changed"].items():
                print(f"      ~  {col}: {ot} → {nt}")
    else:
        print("\n  No column-level differences.")

    print("""
  Merge plan
  ----------
  Base   : new DB (new schema is authoritative)
  jid    : dedupe by raw_string; build old→new ID map
  chat   : dedupe by jid_row_id; build old→new ID map
  message: offset _id by PK_BUMP (> max existing _id); remap chat_row_id,
           sender_jid_row_id, and all *_jid_row_id columns
  Deps   : all tables with message_row_id get +PK_BUMP;
           *_jid_row_id columns remapped; chat_row_id remapped
  Old-only tables : INSERT with FK remapping if schema-compatible
  New-only tables : already in base — untouched
  Old-only columns: dropped (new schema is base)
  New-only columns: backfilled with NULL / column default
""")

    # Report
    def col_diff_md(diffs):
        if not diffs:
            return "*(no column differences)*"
        lines = []
        for tbl, d in sorted(diffs.items()):
            lines.append(f"\n#### `{tbl}`")
            for col, typ in d["added"].items():
                lines.append(f"- **+** `{col}` `{typ}` — new only; backfill NULL")
            for col, typ in d["removed"].items():
                lines.append(f"- **−** `{col}` `{typ}` — old only; dropped")
            for col, (ot, nt) in d["changed"].items():
                lines.append(f"- **~** `{col}`: `{ot}` → `{nt}`")
        return "\n".join(lines)

    report_append(f"""## Gate 2 — Schema reconciliation

### Tables only in OLD ({len(only_old)})
{chr(10).join("- `"+t+"`" for t in only_old) or "*(none)*"}

### Tables only in NEW ({len(only_new)})
{chr(10).join("- `"+t+"`" for t in only_new) or "*(none)*"}

### Column diffs in shared tables
{col_diff_md(col_diffs)}

### Merge plan
- Base = **new** DB schema
- `jid` dedupe by `raw_string`
- `chat` dedupe by `jid_row_id`
- `message._id` offset by PK\\_BUMP = max(new _id) rounded up to next 10 M
- Dependent table `message_row_id` columns: +PK\\_BUMP
- All `*_jid_row_id` columns: remapped via jid\\_map
- All `chat_row_id` columns: remapped via chat\\_map""")

    print(f"  Report: {REPORT}")
    print("  ► GATE 2 — review merge plan above,")
    print("    then run:  python output/merge.py phase3")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — FK REMAPPING + MERGE
# ══════════════════════════════════════════════════════════════════════════════

def phase3():
    print("=" * 62)
    print("  PHASE 3 — FK remapping + merge")
    print("=" * 62)

    for db in [OLD_DB, NEW_DB]:
        if not db.exists():
            sys.exit(f"ERROR: {db.name} not found. Run phase1 first.")
    if MERGED_DB.exists():
        print("  merged.db already exists — delete it to re-run this phase.")
        return

    # ── Setup ──────────────────────────────────────────────────────────────
    print("\n  Copying new_msgstore.db → merged.db ...", end=" ", flush=True)
    shutil.copy2(str(NEW_DB), str(MERGED_DB))
    print("OK")

    mrg = sqlite3.connect(str(MERGED_DB))
    mrg.execute("PRAGMA foreign_keys = OFF")
    mrg.execute("PRAGMA journal_mode = WAL")
    mrg.execute("PRAGMA synchronous = NORMAL")
    mrg.execute("PRAGMA cache_size = -131072")   # 128 MB

    old = sqlite3.connect(str(OLD_DB))

    old_tbls = {t for t in tbl_list(old) if not is_skip(t)}
    mrg_tbls = {t for t in tbl_list(mrg) if not is_skip(t)}
    fts      = fts_roots(mrg)

    def mrg_cols(tbl):
        return [r[1] for r in tbl_info(mrg, tbl)]

    def old_cols(tbl):
        return [r[1] for r in tbl_info(old, tbl)]

    def mrg_pk(tbl):
        return [r[1] for r in tbl_info(mrg, tbl) if r[5] > 0]

    # ── STEP 1: jid deduplication ──────────────────────────────────────────
    print("\n  [Step 1] jid deduplication ...")
    jid_map = {}

    m_jid_cols = mrg_cols("jid")
    o_jid_cols = old_cols("jid")
    ins_cols   = [c for c in m_jid_cols if c != "_id" and c in o_jid_cols]

    old_jids = old.execute(
        "SELECT _id, raw_string, " + ",".join(f"`{c}`" for c in ins_cols)
        + " FROM jid"
    ).fetchall()

    added_jids = 0
    mrg.execute("BEGIN")
    for row in old_jids:
        old_id, raw = row[0], row[1]
        ex = mrg.execute("SELECT _id FROM jid WHERE raw_string=?", (raw,)).fetchone()
        if ex:
            jid_map[old_id] = ex[0]
        else:
            ph = ",".join("?" * len(ins_cols))
            cs = ",".join(f"`{c}`" for c in ins_cols)
            mrg.execute(
                f"INSERT INTO jid (raw_string,{cs}) VALUES (?,{ph})",
                (raw, *row[2:])
            )
            jid_map[old_id] = mrg.lastrowid
            added_jids += 1
    mrg.execute("COMMIT")
    deduped = len(old_jids) - added_jids
    print(f"    {len(old_jids)} old jids → {deduped} deduped, {added_jids} inserted")

    # ── STEP 2: chat deduplication ─────────────────────────────────────────
    print("\n  [Step 2] chat deduplication ...")
    chat_map = {}

    m_chat_cols = mrg_cols("chat")
    o_chat_cols = old_cols("chat")
    c_ins_cols  = [c for c in m_chat_cols if c not in ("_id", "jid_row_id") and c in o_chat_cols]

    old_chats = old.execute(
        "SELECT _id, jid_row_id, " + ",".join(f"`{c}`" for c in c_ins_cols)
        + " FROM chat"
    ).fetchall()

    added_chats = skipped_chats = 0
    mrg.execute("BEGIN")
    for row in old_chats:
        old_cid, old_jid = row[0], row[1]
        new_jid = jid_map.get(old_jid)
        if new_jid is None:
            skipped_chats += 1
            continue
        ex = mrg.execute("SELECT _id FROM chat WHERE jid_row_id=?", (new_jid,)).fetchone()
        if ex:
            chat_map[old_cid] = ex[0]
        else:
            ph = ",".join("?" * len(c_ins_cols))
            cs = ",".join(f"`{c}`" for c in c_ins_cols)
            mrg.execute(
                f"INSERT INTO chat (jid_row_id,{cs}) VALUES (?,{ph})",
                (new_jid, *row[2:])
            )
            chat_map[old_cid] = mrg.lastrowid
            added_chats += 1
    mrg.execute("COMMIT")
    deduped_c = len(old_chats) - added_chats - skipped_chats
    print(f"    {len(old_chats)} old chats → {deduped_c} deduped, {added_chats} inserted, {skipped_chats} skipped (unmapped jid)")

    # ── STEP 3: PK_BUMP ────────────────────────────────────────────────────
    max_id = mrg.execute("SELECT MAX(_id) FROM message").fetchone()[0] or 0
    PK_BUMP = ((max_id // 10_000_000) + 1) * 10_000_000
    print(f"\n  [Step 3] PK_BUMP = {PK_BUMP:,}  (max existing message._id = {max_id:,})")

    # ── STEP 4: messages ───────────────────────────────────────────────────
    print("\n  [Step 4] Inserting messages ...")

    m_msg_cols = mrg_cols("message")
    o_msg_cols = old_cols("message")
    msg_cols   = [c for c in m_msg_cols if c != "_id" and c in o_msg_cols]

    msg_jid_fks  = [c for c in msg_cols if "jid_row_id" in c]
    msg_chat_fks = [c for c in msg_cols if c == "chat_row_id"]
    ci = {c: i for i, c in enumerate(msg_cols)}

    old_msgs = old.execute(
        "SELECT _id, " + ",".join(f"`{c}`" for c in msg_cols) + " FROM message"
    ).fetchall()

    ins_ph = ",".join("?" * (len(msg_cols) + 1))
    ins_cs = "_id, " + ",".join(f"`{c}`" for c in msg_cols)
    m_ins = m_skip = 0

    mrg.execute("BEGIN")
    for row in old_msgs:
        v = list(row[1:])
        for c in msg_chat_fks:
            if v[ci[c]] is not None:
                v[ci[c]] = chat_map.get(v[ci[c]])
        for c in msg_jid_fks:
            if v[ci[c]] is not None:
                v[ci[c]] = jid_map.get(v[ci[c]])
        try:
            mrg.execute(f"INSERT OR IGNORE INTO message ({ins_cs}) VALUES ({ins_ph})",
                        (row[0] + PK_BUMP, *v))
            m_ins += 1
        except sqlite3.Error:
            m_skip += 1
    mrg.execute("COMMIT")
    print(f"    {m_ins:,} inserted, {m_skip} skipped")

    # ── STEP 5: dependent tables ────────────────────────────────────────────
    print("\n  [Step 5] Dependent tables ...")
    ledger = {}
    done   = {"jid", "chat", "message"}

    for tbl in sorted(old_tbls - done):
        if is_skip(tbl):
            continue
        if tbl not in mrg_tbls:
            ledger[tbl] = (0, 0, "not in new schema — skipped")
            continue

        mc = mrg_cols(tbl)
        oc = old_cols(tbl)
        cc = [c for c in mc if c in oc]  # common cols (new schema as base)

        msg_fks    = [c for c in cc if c == "message_row_id"]
        quoted_fks = [c for c in cc if "quoted_row_id" in c]
        jid_fks    = [c for c in cc if "jid_row_id" in c]
        chat_fks   = [c for c in cc if c == "chat_row_id"]
        ci2 = {c: i for i, c in enumerate(cc)}

        try:
            rows = old.execute(
                "SELECT " + ",".join(f"`{c}`" for c in cc) + f" FROM `{tbl}`"
            ).fetchall()
        except sqlite3.Error as e:
            ledger[tbl] = (0, 0, f"read error: {e}")
            continue

        ph  = ",".join("?" * len(cc))
        cs2 = ",".join(f"`{c}`" for c in cc)
        ti = tj = 0
        mrg.execute("BEGIN")
        for row in rows:
            v = list(row)
            for c in msg_fks + quoted_fks:
                if v[ci2[c]] is not None:
                    v[ci2[c]] += PK_BUMP
            for c in jid_fks:
                if v[ci2[c]] is not None:
                    v[ci2[c]] = jid_map.get(v[ci2[c]])
            for c in chat_fks:
                if v[ci2[c]] is not None:
                    v[ci2[c]] = chat_map.get(v[ci2[c]])
            try:
                mrg.execute(f"INSERT OR IGNORE INTO `{tbl}` ({cs2}) VALUES ({ph})", v)
                ti += 1
            except sqlite3.Error:
                tj += 1
        mrg.execute("COMMIT")
        ledger[tbl] = (ti, tj, "")
        note = f"  ({ti} in, {tj} skip)"
        print(f"    {tbl}{note}")

    # ── STEP 6: rebuild FTS ────────────────────────────────────────────────
    print("\n  [Step 6] Rebuilding FTS indexes ...")
    for root in fts:
        try:
            mrg.execute(f"INSERT INTO `{root}`(`{root}`) VALUES('rebuild')")
            mrg.commit()
            print(f"    Rebuilt: {root}")
        except sqlite3.Error as e:
            print(f"    Skipped {root}: {e}")

    # ── STEP 7: VACUUM ─────────────────────────────────────────────────────
    print("\n  [Step 7] VACUUM ...", end=" ", flush=True)
    mrg.isolation_level = None
    mrg.execute("VACUUM")
    mrg.isolation_level = ""
    print("done")

    total_msgs  = mrg.execute("SELECT COUNT(*) FROM message").fetchone()[0]
    total_chats = mrg.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
    old.close(); mrg.close()

    ledger_rows = "\n".join(
        f"| `{t}` | {v[0]:,} | {v[1]} | {v[2]} |"
        for t, v in sorted(ledger.items())
    )
    report_append(f"""## Gate 3 — Merge ledger

PK\\_BUMP = **{PK_BUMP:,}**

| Table | Inserted | Skipped | Note |
|-------|----------|---------|------|
| `jid` | {added_jids} new + {deduped} deduped | — | dedupe by raw_string |
| `chat` | {added_chats} new + {deduped_c} deduped | {skipped_chats} | dedupe by jid_row_id |
| `message` | {m_ins:,} | {m_skip} | offset by PK_BUMP |
{ledger_rows}

**Merged DB:** {total_msgs:,} messages · {total_chats:,} chats""")

    print()
    print("─" * 62)
    print("  GATE 3")
    print("─" * 62)
    print(f"  jid    : {len(old_jids)} old → {added_jids} new, {deduped} deduped")
    print(f"  chat   : {len(old_chats)} old → {added_chats} new, {deduped_c} deduped, {skipped_chats} skip")
    print(f"  message: {m_ins:,} inserted, {m_skip} skipped")
    print(f"  Total  : {total_msgs:,} messages · {total_chats:,} chats")
    print(f"\n  Report: {REPORT}")
    print("  ► run:  python output/merge.py phase4")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — VERIFY
# ══════════════════════════════════════════════════════════════════════════════

def phase4():
    print("=" * 62)
    print("  PHASE 4 — Verify")
    print("=" * 62)

    if not MERGED_DB.exists():
        sys.exit("ERROR: merged.db not found. Run phase3 first.")

    con = sqlite3.connect(str(MERGED_DB))
    con.row_factory = sqlite3.Row

    ic   = con.execute("PRAGMA integrity_check").fetchone()[0]
    fkvs = con.execute("PRAGMA foreign_key_check").fetchall()
    print(f"\n  integrity_check    : {ic}")
    print(f"  foreign_key_check  : {len(fkvs)} violation(s)")

    # Spot checks
    print()
    checks = [
        ("2018", 1514764800000, 1546300800000),
        ("2021", 1609459200000, 1640995200000),
        ("2026", 1735689600000, 1767225600000),
    ]
    for year, lo, hi in checks:
        try:
            rows = con.execute("""
                SELECT m._id, m.timestamp, m.from_me,
                       mt.text,
                       j.raw_string AS sender
                FROM message m
                LEFT JOIN message_text  mt ON mt.message_row_id = m._id
                LEFT JOIN jid           j  ON j._id = m.sender_jid_row_id
                WHERE m.timestamp BETWEEN ? AND ?
                  AND mt.text IS NOT NULL
                LIMIT 3
            """, (lo, hi)).fetchall()
        except sqlite3.Error as e:
            print(f"  [{year}] query error: {e}")
            continue

        if rows:
            print(f"  [{year}] {len(rows)} sample message(s):")
            for r in rows:
                sndr = r["sender"] or ("me" if r["from_me"] else "?")
                txt  = (r["text"] or "")[:70].replace("\n", " ")
                print(f"    {ts(r['timestamp'])}  {sndr[:28]:28s}  {txt!r}")
        else:
            print(f"  [{year}] no text messages found in this window.")
        print()

    total_msgs  = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
    total_chats = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
    ts_lo  = con.execute("SELECT MIN(timestamp) FROM message").fetchone()[0]
    ts_hi  = con.execute("SELECT MAX(timestamp) FROM message").fetchone()[0]
    con.close()

    fk_note = ""
    if fkvs:
        fk_note = "\n".join(str(tuple(r)) for r in fkvs[:10])

    report_append(f"""## Gate 4 — Verification

| Check | Result |
|-------|--------|
| integrity\\_check | {ic} |
| foreign\\_key\\_check | {len(fkvs)} violation(s) |
| Total messages | {total_msgs:,} |
| Total chats | {total_chats:,} |
| Date range | {ts(ts_lo)} → {ts(ts_hi)} |

{"```\\n" + fk_note + "\\n```" if fk_note else ""}""")

    print(f"  Total messages : {total_msgs:,}")
    print(f"  Total chats    : {total_chats:,}")
    print(f"  Date range     : {ts(ts_lo)}  →  {ts(ts_hi)}")
    print(f"  Report: {REPORT}")
    print("  ► run:  python output/merge.py phase5")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — MEDIA RECONCILIATION
# ══════════════════════════════════════════════════════════════════════════════

def phase5():
    print("=" * 62)
    print("  PHASE 5 — Media reconciliation")
    print("=" * 62)

    if not MERGED_DB.exists():
        sys.exit("ERROR: merged.db not found. Run phase3 first.")

    # Re-derive PK_BUMP from new DB max
    nc = sqlite3.connect(str(NEW_DB))
    new_max = nc.execute("SELECT MAX(_id) FROM message").fetchone()[0] or 0
    nc.close()
    PK_BUMP_lo = ((new_max // 10_000_000) + 1) * 10_000_000
    print(f"\n  Old-phone messages have _id >= {PK_BUMP_lo:,}")

    con = sqlite3.connect(str(MERGED_DB))
    con.row_factory = sqlite3.Row

    # Try to get media rows for old-phone messages
    for query in [
        # Full version with chat join
        """SELECT mm.message_row_id,
                  c_j.raw_string AS chat_jid,
                  m.timestamp,
                  mm.file_path,
                  mm.mime_type,
                  mm.file_size,
                  mm.media_name
           FROM message_media mm
           JOIN message m       ON m._id        = mm.message_row_id
           JOIN chat c          ON c._id        = m.chat_row_id
           JOIN jid c_j         ON c_j._id      = c.jid_row_id
           WHERE mm.message_row_id >= ?
           ORDER BY m.timestamp""",
        # Simplified fallback
        """SELECT mm.message_row_id,
                  NULL AS chat_jid,
                  m.timestamp,
                  mm.file_path,
                  mm.mime_type,
                  mm.file_size,
                  NULL AS media_name
           FROM message_media mm
           JOIN message m ON m._id = mm.message_row_id
           WHERE mm.message_row_id >= ?
           ORDER BY m.timestamp""",
    ]:
        try:
            rows = con.execute(query, (PK_BUMP_lo,)).fetchall()
            break
        except sqlite3.Error as e:
            last_err = e
    else:
        con.close()
        sys.exit(f"ERROR: cannot query message_media: {last_err}")

    print(f"  {len(rows):,} old-phone media rows found")

    # Write CSV
    with open(MEDIA_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["message_row_id", "chat_jid", "date",
                    "file_path", "mime_type", "file_size", "media_name"])
        for r in rows:
            w.writerow([r["message_row_id"], r["chat_jid"] or "",
                        ts(r["timestamp"]), r["file_path"] or "",
                        r["mime_type"] or "", r["file_size"] or "",
                        r["media_name"] or ""])
    print(f"  Written: {MEDIA_CSV}")

    # Group by WhatsApp subfolder
    folder_stats = defaultdict(lambda: {"count": 0, "size": 0})
    for r in rows:
        fp = (r["file_path"] or "").replace("\\", "/")
        folder = "Unknown"
        parts = fp.split("/")
        for i, part in enumerate(parts):
            if i + 1 < len(parts) and part in ("Media", "WhatsApp"):
                folder = parts[i + 1]
                break
        folder_stats[folder]["count"] += 1
        folder_stats[folder]["size"] += r["file_size"] or 0

    # Optional cross-check
    old_media_dir = ROOT / "old_media"
    cc_note = "*(No `old_media/` directory found — skipping cross-check.)*"
    if old_media_dir.is_dir():
        local_names = {f.name for f in old_media_dir.rglob("*") if f.is_file()}
        found = sum(1 for r in rows
                    if (r["file_path"] or "").split("/")[-1].split("\\")[-1] in local_names)
        missing = len(rows) - found
        cov = round(found / len(rows) * 100, 1) if rows else 0
        cc_note = f"Cross-check vs `old_media/`: {found} found, {missing} missing, {cov}% coverage"
        print(f"\n  {cc_note}")

    con.close()

    folder_md = "\n".join(
        f"| {f} | {s['count']:,} | {s['size']/1024/1024:.1f} MB |"
        for f, s in sorted(folder_stats.items(), key=lambda x: -x[1]["count"])
    )
    report_append(f"""## Gate 5 — Media reconciliation

Old-phone media rows (message\\_row\\_id ≥ {PK_BUMP_lo:,}): **{len(rows):,}**

| Folder | Files | Size |
|--------|-------|------|
{folder_md}

{cc_note}

> Media files live in `WhatsApp/Media/` on the phone.
> The DB only holds references. Copy the old phone's Media folder to
> the new phone to restore photos, videos, and voice notes.
> See RESTORE.md for exact steps.""")

    print()
    print("─" * 62)
    print("  GATE 5 — Media by folder")
    print("─" * 62)
    for folder, s in sorted(folder_stats.items(), key=lambda x: -x[1]["count"]):
        print(f"  {folder:35s}  {s['count']:5,} files  {s['size']/1024/1024:7.1f} MB")
    print(f"\n  Report: {REPORT}")
    print("  ► run:  python output/merge.py phase6")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — RE-ENCRYPT + RESTORE.md
# ══════════════════════════════════════════════════════════════════════════════

def phase6():
    print("=" * 62)
    print("  PHASE 6 — Re-encrypt + RESTORE.md")
    print("=" * 62)

    if not MERGED_DB.exists():
        sys.exit("ERROR: merged.db not found. Run phase3 first.")

    new_key = read_key(NEW_KEY_F)
    print("  [OK] NEW_KEY read — not printed.")

    if MERGED_CRYPT.exists():
        MERGED_CRYPT.unlink()
    print("  Re-encrypting merged.db ...", end=" ", flush=True)
    run_encrypt(new_key, NEW_CRYPT, MERGED_DB, MERGED_CRYPT)
    size = MERGED_CRYPT.stat().st_size
    print(f"OK  ({size:,} bytes / {size/1024/1024:.1f} MB)")

    con = sqlite3.connect(str(MERGED_DB))
    total_msgs  = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
    total_chats = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
    ts_lo = con.execute("SELECT MIN(timestamp) FROM message").fetchone()[0]
    ts_hi = con.execute("SELECT MAX(timestamp) FROM message").fetchone()[0]
    con.close()

    RESTORE_MD.write_text(textwrap.dedent(f"""\
    # WhatsApp Merge — Restore Playbook
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

    **Merged backup:** {total_msgs:,} messages · {total_chats:,} chats
    **Date range:** {ts(ts_lo)} → {ts(ts_hi)}

    ---

    ## Step 0 — Make a rollback backup FIRST

    Before touching anything, back up the **new phone's** current WhatsApp to Google Drive:

    1. WhatsApp → ⋮ → Settings → Chats → Chat Backup → **Back Up Now**
    2. Wait for the Google Drive upload to complete and note the timestamp.

    This is your rollback. If anything goes wrong you can always restore from Drive.

    ---

    ## Step 1 — Copy the merged backup to your new phone

    1. Connect the **new phone** to your PC via USB cable.
    2. On the phone: pull down the notification shade → tap **Charging via USB**
       → select **File Transfer**.
    3. In Windows File Explorer, open the phone and navigate to:

       ```
       Internal storage / Android / media / com.whatsapp / WhatsApp / Databases /
       ```

    4. Copy **`output/msgstore.db.crypt15`** into that Databases folder,
       overwriting the existing file.
       The filename **must** be exactly `msgstore.db.crypt15`.

    ---

    ## Step 2 — Copy old-phone media (optional but recommended)

    To restore old photos, videos, and voice notes:

    1. From your old phone (or an old-phone backup on PC), copy:
       ```
       Internal storage / WhatsApp / Media /
       ```
       (or the Android 11+ path: `Android/media/com.whatsapp/WhatsApp/Media/`)

    2. Paste into the **new phone's**:
       ```
       Internal storage / Android / media / com.whatsapp / WhatsApp / Media /
       ```
       Choose **Merge** (not Replace all) so new-phone media is preserved.

    See `output/media_manifest.csv` for the full list of old-phone media files.

    ---

    ## Step 3 — Uninstall WhatsApp from the new phone

    Long-press the WhatsApp icon → **Uninstall** (not just "Clear data").
    This removes the app while leaving the Databases folder you just populated.

    ---

    ## Step 4 — Reinstall and restore

    1. Install WhatsApp from the Play Store.
    2. Sign in with the **new phone's number**.
    3. When prompted to restore a backup → choose **Restore from local backup**.
    4. When asked for the backup encryption key, enter the **new phone's**
       64-digit hex key (the same key that was in `new-phone/key.txt`).
    5. Wait for restore to complete. Large backups can take several minutes.

    ---

    ## Step 5 — Verify

    - Check that old chats appear (messages pre-2025).
    - Check that recent chats appear (2025–2026).
    - Spot-check a few media messages to confirm photos/videos load.
    - The oldest message date should be around 2015–2016.

    ---

    ## Troubleshooting

    ### "Invalid key / can't decrypt backup"
    - Make sure you entered the **new phone's** key, not the old phone's.
    - The key must be exactly 64 lowercase hex characters, no spaces or newlines.
    - If copied from the WhatsApp UI, check no characters were cut off.

    ### Phone shows no local backup to restore
    - Verify the filename is exactly `msgstore.db.crypt15` (lowercase, no extra chars).
    - Verify the path on the phone:
      `Internal storage / Android / media / com.whatsapp / WhatsApp / Databases /`
      (not the old path `WhatsApp/Databases/`).
    - WhatsApp restores the **newest** .crypt15 file present. If an older one
      is in the same folder, delete it.

    ### "Backup format not supported" / schema rejection
    The merged DB uses the new phone's schema as its base, so this should not
    happen. If it does:
    - **Fallback:** keep the new phone as-is for current chats, and view old
      chats via DB Browser for SQLite pointed at `output/merged.db`.
      All 11 years of history are in that file — just not in the WhatsApp UI.

    ### How to roll back completely
    1. Uninstall WhatsApp on the new phone.
    2. Reinstall → sign in → when prompted, choose **Restore from Google Drive**
       (the backup made in Step 0).
    3. This returns the new phone to exactly how it was before the merge.

    ---

    ## Deliverables

    | File | Purpose |
    |------|---------|
    | `output/msgstore.db.crypt15` | Merged re-encrypted backup |
    | `output/media_manifest.csv`  | List of old-phone media needing transfer |
    | `output/merge_report.md`     | Full audit of the merge |
    | `output/RESTORE.md`          | This file |
    | `output/merge.py`            | Reproducible merge script |
    """), encoding="utf-8")

    report_append(f"""## Gate 6 — Re-encryption

| | |
|---|---|
| Output | `output/msgstore.db.crypt15` |
| Size | {size:,} bytes ({size/1024/1024:.1f} MB) |
| Reference | `new-phone/msgstore.db.crypt15` |
| Key | NEW\\_KEY (not logged) |

RESTORE.md written. All deliverables in `./output/`.""")

    print()
    print("─" * 62)
    print("  GATE 6 — Complete")
    print("─" * 62)
    print(f"  output/msgstore.db.crypt15  {size:,} bytes ({size/1024/1024:.1f} MB)")
    print(f"  output/RESTORE.md           written")
    print()
    print("  Deliverables:")
    for fname in ["msgstore.db.crypt15", "merge.py", "merge_report.md",
                  "media_manifest.csv", "RESTORE.md"]:
        p = OUT_DIR / fname
        tick = "[OK]" if p.exists() else "[--]"
        size_s = f"  {p.stat().st_size:,} bytes" if p.exists() else ""
        print(f"    {tick}  {fname}{size_s}")
    print(f"\n  Report: {REPORT}")
    print("  All done!")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

PHASES = {
    "phase1": phase1,
    "phase2": phase2,
    "phase3": phase3,
    "phase4": phase4,
    "phase5": phase5,
    "phase6": phase6,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in PHASES:
        print(__doc__)
        print("Available phases:", ", ".join(PHASES))
        # Resume hint
        if OLD_DB.exists() and NEW_DB.exists():
            if MERGED_DB.exists():
                print("\nResume: merged.db found → start at phase4")
            else:
                print("\nResume: decrypted DBs found → start at phase2")
        sys.exit(1)
    PHASES[sys.argv[1]]()
