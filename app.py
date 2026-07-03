"""
WhatsApp Backup Merger — local web interface.
Binds only to 127.0.0.1; no data ever leaves your machine.
"""
import io, os, uuid, json, threading, queue, shutil, webbrowser, zipfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, send_file

app = Flask(__name__)
app.secret_key = os.urandom(32)

JOBS      = {}
WORK_ROOT = Path("jobs")
OUT_DIR   = Path("output")

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start():
    required = ["old_crypt", "old_key", "new_crypt", "new_key"]

    job_id   = str(uuid.uuid4())[:8]
    work_dir = WORK_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    paths = {}
    for field in required:
        f = request.files.get(field)
        if not f or f.filename == "":
            shutil.rmtree(work_dir, ignore_errors=True)
            return jsonify(error=f"Missing file: {field}"), 400
        ext  = Path(f.filename).suffix or ""
        dest = work_dir / (field + ext)
        f.save(str(dest))
        paths[field] = dest

    # Optional: path to old media folder on this machine
    old_media_path = (request.form.get("old_media_path") or "").strip() or None

    q = queue.Queue()
    JOBS[job_id] = {"status": "running", "q": q}

    threading.Thread(
        target=_worker,
        args=(job_id, paths, work_dir, old_media_path),
        daemon=True,
    ).start()

    return jsonify(job_id=job_id)


def _worker(job_id, paths, work_dir, old_media_path):
    import pipeline as p

    job = JOBS[job_id]
    q   = job["q"]

    def emit(phase, pct, msg):
        q.put({"type": "progress", "phase": phase, "pct": pct, "msg": msg})

    def gate(num, data):
        q.put({"type": "gate", "gate": num, "data": data})
        job[f"gate{num}"] = data

    try:
        gate(1, p.phase1_decrypt(
            paths["old_crypt"], paths["old_key"],
            paths["new_crypt"], paths["new_key"],
            work_dir, emit,
        ))
        gate(2, p.phase2_schema(work_dir, emit))

        g3 = p.phase3_merge(work_dir, emit)
        gate(3, g3)

        gate(4, p.phase4_encrypt(
            paths["new_crypt"], paths["new_key"],
            work_dir, OUT_DIR, emit,
        ))

        gate(5, p.phase5_media(
            work_dir, old_media_path, OUT_DIR, emit,
            old_msg_offset=g3.get("old_msg_offset", 1_000_000),
        ))

        gates_for_report = {n: job.get(f"gate{n}", {}) for n in range(1, 6)}
        gate(6, p.phase6_playbook(OUT_DIR, gates_for_report, emit))

        p.write_merge_report(OUT_DIR, gates_for_report)

        job["status"] = "done"
        q.put({"type": "done"})

    except Exception as e:
        job["status"] = "error"
        job["error"]  = str(e)
        q.put({"type": "error", "message": str(e)})


@app.route("/events/<job_id>")
def events(job_id):
    if job_id not in JOBS:
        return "job not found", 404

    def generate():
        q = JOBS[job_id]["q"]
        while True:
            try:
                ev = q.get(timeout=30)
                yield f"data: {json.dumps(ev)}\n\n"
                if ev["type"] in ("done", "error"):
                    break
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/download/<job_id>/<filename>")
def download_file(job_id, filename):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return "not ready", 404
    # Restrict to known output files
    allowed = {
        "msgstore.db.crypt15",
        "media_manifest.csv",
        "media_summary.md",
        "restore_playbook.md",
        "merge_report.md",
    }
    if filename not in allowed:
        return "not found", 404
    out = OUT_DIR / filename
    if not out.exists():
        return "file not found", 404
    return send_file(str(out.resolve()), as_attachment=True, download_name=filename)


@app.route("/download-all/<job_id>")
def download_all(job_id):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return "not ready", 404

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in OUT_DIR.iterdir():
            if f.is_file():
                zf.write(f, f.name)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name="whatsapp_merge_output.zip",
        mimetype="application/zip",
    )


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    WORK_ROOT.mkdir(exist_ok=True)
    OUT_DIR.mkdir(exist_ok=True)

    print("\n" + "=" * 52)
    print("  WhatsApp Backup Merger")
    print("  http://127.0.0.1:5000")
    print("  (nothing leaves your machine)")
    print("=" * 52 + "\n")

    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
