"""
Runs Phases 2-6 against fake databases created by create_test_data.py.
No real phone files or decryption needed.

  python create_test_data.py
  python test_merge.py
"""
import sys, sqlite3
from pathlib import Path

WORK   = Path("work")
OUTPUT = Path("output")

def check(condition, label):
    icon = "PASS" if condition else "FAIL"
    print(f"  [{icon}]  {label}")
    if not condition:
        sys.exit(1)

print("=" * 52)
print("  WhatsApp Merge - pipeline test")
print("=" * 52)

for f in ("old_msgstore.db", "new_msgstore.db"):
    check((WORK / f).exists(), f"work/{f} exists")

import pipeline as p

def noop(phase, pct, msg):
    pass

print("\n[Phase 2] Schema diff...")
gate2 = p.phase2_schema(WORK, noop)
check(len(gate2["mergeable"]) > 0,      f"{len(gate2['mergeable'])} mergeable tables found")
check("message" in gate2["mergeable"],  "'message' in merge list")
check("jid"     in gate2["mergeable"],  "'jid' in merge list")
check("chat"    in gate2["mergeable"],  "'chat' in merge list")

print("\n[Phase 3] Merge...")
(WORK / "merged.db").unlink(missing_ok=True)
gate3 = p.phase3_merge(WORK, noop)
check(gate3["integrity"] == "ok",            f"integrity_check = {gate3['integrity']}")
check(gate3["total_messages"] > 0,           f"{gate3['total_messages']:,} total messages")
check(gate3["total_chats"] > 0,              f"{gate3['total_chats']} total chats")
check(min(gate3["per_year"].keys()) <= 2015, f"earliest year = {min(gate3['per_year'].keys())}")
check(max(gate3["per_year"].keys()) >= 2026, f"latest year   = {max(gate3['per_year'].keys())}")
check(gate3["fk_violations"] == 0,           f"FK violations = {gate3['fk_violations']}")

con = sqlite3.connect(str(WORK / "merged.db"))
old_msgs    = con.execute("SELECT COUNT(*) FROM message WHERE timestamp < 1451606400000").fetchone()[0]
media_count = con.execute("SELECT COUNT(*) FROM message_media").fetchone()[0]
con.close()
check(old_msgs > 0,    f"{old_msgs} pre-2016 messages present")
check(media_count > 0, f"{media_count} message_media rows exist")

print("\n[Phase 5] Media reconciliation...")
OUTPUT.mkdir(exist_ok=True)
gate5 = p.phase5_media(WORK, None, OUTPUT, noop,
                        old_msg_offset=gate3.get("old_msg_offset", 1_000_000))
check(gate5["total_media"] > 0,                       f"{gate5['total_media']} total media rows")
check(gate5["old_media"] > 0,                         f"{gate5['old_media']} old-origin rows")
check((OUTPUT / "media_manifest.csv").exists(),        "media_manifest.csv written")
check((OUTPUT / "media_summary.md").exists(),          "media_summary.md written")

print("\n[Phase 6] Restore playbook...")
gates_all = {3: gate3, 4: {}, 5: gate5}
p.phase6_playbook(OUTPUT, gates_all, noop)
check((OUTPUT / "restore_playbook.md").exists(),       "restore_playbook.md written")

print("\n[Report] merge_report.md...")
p.write_merge_report(OUTPUT, gates_all)
check((OUTPUT / "merge_report.md").exists(),           "merge_report.md written")

print("\n[Results]")
print(f"  Total messages : {gate3['total_messages']:,}")
print(f"  Date range     : {gate3['date_min']} to {gate3['date_max']}")
print(f"  Old media files: {gate5['old_media']}")
print()
print("  Messages per year:")
for yr, cnt in sorted(gate3["per_year"].items()):
    print(f"    {yr}  {cnt:>4}  {'#' * (cnt // 3)}")
print()
print("  Output files:")
for f in ("media_manifest.csv","media_summary.md","restore_playbook.md","merge_report.md"):
    size = (OUTPUT / f).stat().st_size
    print(f"    {f:<32} {size:,} bytes")
print()
print("  All checks passed - pipeline is working correctly.")
