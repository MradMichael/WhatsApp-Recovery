"""
WhatsApp Backup Merger — local web interface.
Binds only to 127.0.0.1; no data ever leaves your machine.
"""
import os, uuid, json, threading, queue, shutil, webbrowser
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, send_file

app = Flask(__name__)
app.secret_key = os.urandom(32)

JOBS      = {}           # job_id -> state dict
WORK_ROOT = Path("jobs")
OUT_DIR   = Path("output")


# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start():
    fields = ["old_crypt", "old_key", "new_crypt", "new_key"]

    job_id   = str(uuid.uuid4())[:8]
    work_dir = WORK_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    paths = {}
    for field in fields:
        f = request.files.get(field)
        if not f or f.filename == "":
            shutil.rmtree(work_dir, ignore_errors=True)
            return jsonify(error=f"Missing file: {field}"), 400
        ext  = Path(f.filename).suffix or ""
        dest = work_dir / (field + ext)
        f.save(str(dest))
        paths[field] = dest

    q = queue.Queue()
    JOBS[job_id] = {"status": "running", "q": q}

    threading.Thread(
        target=_worker, args=(job_id, paths, work_dir), daemon=True
    ).start()

    return jsonify(job_id=job_id)


def _worker(job_id, paths, work_dir):
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
        gate(3, p.phase3_merge(work_dir, emit))
        gate(4, p.phase4_encrypt(
            paths["new_crypt"], paths["new_key"],
            work_dir, OUT_DIR, emit,
        ))

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


@app.route("/download/<job_id>")
def download(job_id):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return "not ready", 404
    out = OUT_DIR / "msgstore.db.crypt15"
    if not out.exists():
        return "output file missing", 404
    return send_file(
        str(out.resolve()),
        as_attachment=True,
        download_name="msgstore.db.crypt15",
    )


# ── entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    WORK_ROOT.mkdir(exist_ok=True)
    OUT_DIR.mkdir(exist_ok=True)

    print("\n" + "━" * 52)
    print("  WhatsApp Backup Merger")
    print("  Running at  http://127.0.0.1:5000")
    print("  (data never leaves your machine)")
    print("━" * 52 + "\n")

    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
