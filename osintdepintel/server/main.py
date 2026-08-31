from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import re
import shutil
import threading
import time
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..ai_summary import OPENCODE_DEFAULT_MODEL, write_opencode_target_summary
from ..config import TargetConfig, load_targets
from ..logger import logger
from ..pipeline import Pipeline
from ..reporting.writers import _safe_filename

app = FastAPI(title="OSINT Dependency Intelligence Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# The read-only "master" target list every visitor starts from. Env-overridable so a
# wheel/container deploy can point it at a real file (a wheel has no examples/).
BASELINE_CONFIG = Path(os.environ.get("OSINT_CONFIG_PATH", PROJECT_ROOT / "examples" / "targets.json"))
# Root under which each visitor gets a private, disposable sandbox (targets + reports).
SESSIONS_ROOT = Path(
    os.environ.get(
        "OSINT_SESSIONS_DIR", Path(os.environ.get("OSINT_OUTPUT_DIR", PROJECT_ROOT / "reports")).parent / "_sessions"
    )
)
# Pre-generated demo reports every new sandbox is seeded with (so the dashboard is not empty).
BASELINE_REPORTS = SESSIONS_ROOT / "_baseline"
BASELINE_REPORT_TARGETS = ["otakuflorist", "juice-shop"]

SESSION_COOKIE = "osint_session"
SESSION_TTL = int(os.environ.get("OSINT_SESSION_TTL", 6 * 3600))  # seconds a sandbox lives
_SWEEP_INTERVAL = 300  # seconds between expiry sweeps


class ScanState:
    def __init__(self) -> None:
        self.running = False
        self.targets: list[str] = []
        self.options: dict[str, Any] = {}
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.error: str | None = None
        self.lock = threading.Lock()


class QueueLogHandler(logging.Handler):
    """Routes log records to one scan's queue only (filtered by the scan thread), so
    concurrent visitors' scans never see each other's log lines."""

    def __init__(self, state: ScanState, thread_ident: int) -> None:
        super().__init__()
        self.state = state
        self.thread_ident = thread_ident
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self.thread_ident:
            return
        self.state.log_queue.put(self.format(record))


class Session:
    def __init__(self, sid: str) -> None:
        self.id = sid
        self.dir = SESSIONS_ROOT / sid
        self.config_path = self.dir / "targets.json"
        self.output_dir = self.dir / "reports"
        self.scan_state = ScanState()
        self.last_access = time.time()


_baseline_built = False
_baseline_lock = threading.Lock()


def build_baseline() -> None:
    """Generate the shared seed reports once (idempotent). Offline + a one-off AI summary
    per report if a key is configured — runs a single time, not per visitor."""
    global _baseline_built
    with _baseline_lock:
        if _baseline_built:
            return
        BASELINE_REPORTS.mkdir(parents=True, exist_ok=True)
        if any(BASELINE_REPORTS.glob("*.json")):
            _baseline_built = True
            return
        try:
            if BASELINE_CONFIG.exists():
                targets = load_targets(BASELINE_CONFIG)
                seed = [t for t in targets if t.name in BASELINE_REPORT_TARGETS]
                if seed:
                    result = Pipeline(offline=True, enable_nvd=False).process_targets(
                        seed, output_dir=BASELINE_REPORTS, include_graph=True
                    )
                    key = os.environ.get("OPENCODE_API_KEY")
                    if key:
                        model = os.environ.get("OPENCODE_MODEL", OPENCODE_DEFAULT_MODEL)
                        for report in result["reports"]:
                            write_opencode_target_summary(
                                report, BASELINE_REPORTS, key, model, report["target"]["name"]
                            )
        except Exception:
            logger.exception("Failed to build baseline demo reports")
        _baseline_built = True


def _seed_session(session: Session) -> None:
    session.output_dir.mkdir(parents=True, exist_ok=True)
    if BASELINE_CONFIG.exists():
        shutil.copyfile(BASELINE_CONFIG, session.config_path)
    else:
        session.config_path.write_text('{"targets": []}', encoding="utf-8")
    build_baseline()
    if BASELINE_REPORTS.exists():
        for f in BASELINE_REPORTS.glob("*"):
            if f.is_file():
                shutil.copyfile(f, session.output_dir / f.name)


class SessionStore:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.lock = threading.Lock()
        self._last_sweep = time.time()

    def get(self, sid: str) -> Session:
        with self.lock:
            self._maybe_sweep()
            session = self.sessions.get(sid)
            if session is None:
                session = Session(sid)
                _seed_session(session)
                self.sessions[sid] = session
            session.last_access = time.time()
            return session

    def _maybe_sweep(self) -> None:
        now = time.time()
        if now - self._last_sweep < _SWEEP_INTERVAL:
            return
        self._last_sweep = now
        cutoff = now - SESSION_TTL
        for sid in [s for s, sess in self.sessions.items() if sess.last_access < cutoff]:
            dead = self.sessions.pop(sid)
            shutil.rmtree(dead.dir, ignore_errors=True)


store = SessionStore()


def _valid_sid(sid: str | None) -> bool:
    return bool(sid) and re.fullmatch(r"[0-9a-f]{32}", sid or "") is not None


def _session(request: Request) -> Session:
    sid = getattr(request.state, "session_id", None) or "default_session_00000000000000000000"
    return store.get(sid)


def save_targets_file(config_path: Path, targets: list[TargetConfig]) -> None:
    with config_path.open("w", encoding="utf-8") as f:
        json.dump({"targets": [t.to_dict() for t in targets]}, f, indent=2)


def parse_url_to_target(url: str) -> dict[str, Any]:
    # Clean URL (add scheme if missing)
    url_val = url.strip()
    if not url_val.startswith(("http://", "https://")):
        url_val = "https://" + url_val

    try:
        parsed = urlparse(url_val)
        hostname = parsed.hostname or ""
        path = parsed.path.strip("/")

        name = ""
        github_repos = []

        if "github.com" in hostname.lower():
            # GitHub URL format: github.com/user/repo/...
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                user = parts[0]
                repo = parts[1]
                if repo.endswith(".git"):
                    repo = repo[:-4]
                name = repo
                github_repos = [f"{user}/{repo}"]
                url_val = f"https://github.com/{user}/{repo}"
            else:
                name = "github-repo"
        else:
            # Regular website URL format
            parts = [p for p in hostname.split(".") if p]
            if len(parts) >= 2:  # noqa: SIM108 - nested ternary would hurt readability
                name = parts[1] if parts[0] == "www" else parts[0]
            else:
                name = hostname or "web-target"

        # Clean target name of unsafe chars
        name = re.sub(r"[^a-zA-Z0-9_-]", "-", name).lower()
        if not name:
            name = "target"

        return {
            "name": name,
            "url": url_val,
            "github_repos": github_repos,
            "sbom_urls": [],
            "container_images": [],
            "mobile_artifacts": [],
            "package_hints": [],
            "metadata": {},
        }
    except Exception as e:
        raise ValueError(f"Failed to parse target URL: {e}") from e


@app.get("/api/targets")
def get_targets(request: Request) -> list[dict[str, Any]]:
    try:
        targets = load_targets(_session(request).config_path)
        return [t.to_dict() for t in targets]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/targets")
def add_target(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        url = payload.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        config_path = _session(request).config_path
        parsed_payload = parse_url_to_target(url)
        targets = load_targets(config_path)

        if any(t.name == parsed_payload["name"] for t in targets):
            raise HTTPException(status_code=400, detail=f"Target '{parsed_payload['name']}' already exists")

        new_target = TargetConfig.from_dict(parsed_payload)
        targets.append(new_target)
        save_targets_file(config_path, targets)
        return {"status": "success", "target": new_target.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.put("/api/targets/{name}")
def update_target(request: Request, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        url = payload.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        config_path = _session(request).config_path
        parsed_payload = parse_url_to_target(url)
        targets = load_targets(config_path)

        index = -1
        for i, t in enumerate(targets):
            if t.name == name:
                index = i
                break
        if index == -1:
            raise HTTPException(status_code=404, detail=f"Target '{name}' not found")

        updated_target = TargetConfig.from_dict(parsed_payload)
        targets[index] = updated_target
        save_targets_file(config_path, targets)
        return {"status": "success", "target": updated_target.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.delete("/api/targets/{name}")
def delete_target(request: Request, name: str) -> dict[str, str]:
    try:
        config_path = _session(request).config_path
        targets = load_targets(config_path)
        filtered = [t for t in targets if t.name != name]
        if len(filtered) == len(targets):
            raise HTTPException(status_code=404, detail=f"Target '{name}' not found")
        save_targets_file(config_path, filtered)
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports")
def list_reports(request: Request) -> list[dict[str, Any]]:
    try:
        output_dir = _session(request).output_dir
        if not output_dir.exists():
            return []
        reports = []
        for file in output_dir.glob("*.json"):
            if file.name == "aggregate_report.json":
                continue
            # Skip auxiliary SBOM exports; only list actual target intelligence reports.
            if file.name.endswith(("_spdx.json", "_cyclonedx.json")):
                continue
            try:
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                # Validate the file is a target report (not a raw SBOM or other artifact).
                if not isinstance(data, dict) or "target" not in data or "summary" not in data:
                    continue
                reports.append(
                    {
                        "target_name": file.stem,
                        "filename": file.name,
                        "updated_at": file.stat().st_mtime,
                        "dependency_count": data.get("summary", {}).get("dependency_count", 0),
                        "vulnerability_count": data.get("summary", {}).get("vulnerability_count", 0),
                        "finding_count": data.get("summary", {}).get("finding_count", 0),
                    }
                )
            except Exception:
                pass
        return sorted(reports, key=lambda r: r["updated_at"], reverse=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports/detail/{target_name}")
def get_report_detail(request: Request, target_name: str) -> dict[str, Any]:
    report_file = _session(request).output_dir / f"{_safe_filename(target_name)}.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report for target '{target_name}' not found")
    try:
        with report_file.open("r", encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.delete("/api/reports/{target_name}")
def delete_report(request: Request, target_name: str) -> dict[str, str]:
    """Delete a target report and all of its generated artifacts (from this sandbox only)."""
    output_dir = _session(request).output_dir
    safe_stem = _safe_filename(target_name)
    deleted: list[str] = []
    not_found = True
    suffixes = [".json", ".txt", ".dot", "_cyclonedx.json", "_spdx.json", "_opencode_summary.txt"]
    for suffix in suffixes:
        path = output_dir / f"{safe_stem}{suffix}"
        if path.exists():
            path.unlink()
            deleted.append(path.name)
            not_found = False
    if not_found:
        raise HTTPException(status_code=404, detail=f"Report for target '{target_name}' not found")
    return {"status": "success", "deleted": ", ".join(deleted)}


@app.get("/api/reports/aggregate")
def get_aggregate_report(request: Request) -> dict[str, Any]:
    report_file = _session(request).output_dir / "aggregate_report.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Aggregate report not found")
    try:
        with report_file.open("r", encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports/opencode-summary/{target_name}")
def get_opencode_summary(request: Request, target_name: str) -> dict[str, str]:
    summary_file = _session(request).output_dir / f"{_safe_filename(target_name)}_opencode_summary.txt"
    if not summary_file.exists():
        raise HTTPException(status_code=404, detail="OpenCode summary file not found")
    try:
        return {"summary": summary_file.read_text(encoding="utf-8")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports/artifacts/{target_name}")
def list_report_artifacts(request: Request, target_name: str) -> list[dict[str, Any]]:
    """Return the downloadable artifacts available for a target report stem."""
    output_dir = _session(request).output_dir
    if not output_dir.exists():
        return []
    # target_name from the report list is already the on-disk file stem.
    safe_stem = _safe_filename(target_name)
    artifacts: list[dict[str, Any]] = []
    mapping = [
        ("report-json", f"{safe_stem}.json", "application/json", "report.json"),
        ("report-text", f"{safe_stem}.txt", "text/plain", "report.txt"),
        ("graph-dot", f"{safe_stem}.dot", "text/plain", "graph.dot"),
        ("cyclonedx", f"{safe_stem}_cyclonedx.json", "application/json", "sbom.cyclonedx.json"),
        ("spdx", f"{safe_stem}_spdx.json", "application/json", "sbom.spdx.json"),
    ]
    for kind, filename, media_type, download_name in mapping:
        path = output_dir / filename
        if path.exists():
            artifacts.append(
                {
                    "kind": kind,
                    "filename": filename,
                    "download_name": download_name,
                    "media_type": media_type,
                    "size": path.stat().st_size,
                    "url": f"/api/reports/artifact/{target_name}/{kind}",
                }
            )
    # Per-target AI summaries are exposed as downloads for this report stem.
    opencode_file = output_dir / f"{safe_stem}_opencode_summary.txt"
    if opencode_file.exists():
        artifacts.append(
            {
                "kind": "opencode-summary",
                "filename": opencode_file.name,
                "download_name": "opencode-summary.txt",
                "media_type": "text/plain",
                "size": opencode_file.stat().st_size,
                "url": f"/api/reports/artifact/{target_name}/opencode-summary",
            }
        )
    return artifacts


@app.get("/api/reports/artifact/{target_name}/{kind}")
def download_report_artifact(request: Request, target_name: str, kind: str) -> FileResponse:
    """Serve a single report artifact with a friendly download name."""
    output_dir = _session(request).output_dir
    if not output_dir.exists():
        raise HTTPException(status_code=404, detail="Output directory not found")

    # target_name from the report list is already the on-disk file stem.
    safe_stem = _safe_filename(target_name)
    artifact_map = {
        "report-json": (f"{safe_stem}.json", "application/json", "report.json"),
        "report-text": (f"{safe_stem}.txt", "text/plain", "report.txt"),
        "graph-dot": (f"{safe_stem}.dot", "text/plain", "graph.dot"),
        "cyclonedx": (f"{safe_stem}_cyclonedx.json", "application/json", "sbom.cyclonedx.json"),
        "spdx": (f"{safe_stem}_spdx.json", "application/json", "sbom.spdx.json"),
        "opencode-summary": (f"{safe_stem}_opencode_summary.txt", "text/plain", "opencode-summary.txt"),
    }
    if kind not in artifact_map:
        raise HTTPException(status_code=400, detail=f"Unknown artifact kind: {kind}")

    filename, media_type, download_name = artifact_map[kind]
    path = output_dir / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Artifact '{filename}' not found")
    return FileResponse(
        str(path),
        media_type=media_type,
        filename=download_name,
        content_disposition_type="attachment",
    )


@app.get("/api/scans/status")
def get_scan_status(request: Request) -> dict[str, Any]:
    scan_state = _session(request).scan_state
    with scan_state.lock:
        return {
            "running": scan_state.running,
            "targets": scan_state.targets,
            "options": scan_state.options,
            "error": scan_state.error,
        }


def run_scan_thread(
    scan_state: ScanState, config_path: Path, output_dir: Path, targets_to_scan: list[str], options: dict[str, Any]
) -> None:
    handler = QueueLogHandler(scan_state, threading.get_ident())
    logger.addHandler(handler)

    logger.info("Web scan run initiated. Targets: %s", ", ".join(targets_to_scan))
    try:
        all_targets = load_targets(config_path)
        selected_targets = [t for t in all_targets if t.name in targets_to_scan]
        if not selected_targets:
            raise ValueError("No matching targets found to scan")

        offline = options.get("offline", False)
        skip_nvd = options.get("skip_nvd", False)
        # OpenCode AI summaries run when explicitly requested OR whenever an
        # OPENCODE_API_KEY is configured in the environment (the deploy path — no UI toggle).
        opencode_summary = options.get("opencode_summary", False) or bool(os.environ.get("OPENCODE_API_KEY"))
        rate_limit = options.get("rate_limit", 4.0)
        max_enrich_dependencies = options.get("max_enrich_dependencies")

        pipeline = Pipeline(
            offline=offline,
            fixture_path=None,
            max_enrichment_dependencies=max_enrich_dependencies,
            enable_nvd=not skip_nvd,
            rate_limit_rps=rate_limit,
        )

        result = pipeline.process_targets(selected_targets, output_dir=output_dir, include_graph=True)

        # A per-target OpenCode AI summary is written so each website report
        # has its own plain-language explanation.
        if opencode_summary:
            opencode_api_key = options.get("opencode_api_key") or os.environ.get("OPENCODE_API_KEY")
            if not opencode_api_key:
                logger.warning("OpenCode summary requested but no API key was provided")
            else:
                opencode_model = options.get("opencode_model") or os.environ.get(
                    "OPENCODE_MODEL", OPENCODE_DEFAULT_MODEL
                )
                for report in result["reports"]:
                    target_name = report["target"]["name"]
                    logger.info("Requesting OpenCode summary for '%s' using model '%s'...", target_name, opencode_model)
                    write_opencode_target_summary(report, output_dir, opencode_api_key, opencode_model, target_name)
                logger.info("OpenCode summaries complete.")

        logger.info("Web scan run completed successfully.")

    except Exception as e:
        logger.exception("Scan execution failed")
        with scan_state.lock:
            scan_state.error = str(e)
    finally:
        logger.removeHandler(handler)
        with scan_state.lock:
            scan_state.running = False


@app.post("/api/scans/run")
def start_scan(request: Request, payload: dict[str, Any]) -> dict[str, str]:
    session = _session(request)
    scan_state = session.scan_state

    with scan_state.lock:
        if scan_state.running:
            raise HTTPException(status_code=400, detail="A scan is already running")

        targets_to_scan = payload.get("targets", [])
        if not targets_to_scan:
            raise HTTPException(status_code=400, detail="Must specify targets to scan")

        options = payload.get("options", {})
        scan_state.running = True
        scan_state.targets = targets_to_scan
        scan_state.options = options
        scan_state.error = None
        scan_state.log_queue = queue.Queue()

    threading.Thread(
        target=run_scan_thread,
        args=(scan_state, session.config_path, session.output_dir, targets_to_scan, options),
        daemon=True,
    ).start()

    return {"status": "started"}


@app.get("/api/scans/stream-logs")
def stream_logs(request: Request) -> StreamingResponse:
    scan_state = _session(request).scan_state

    async def log_generator() -> AsyncGenerator[str, None]:
        # Stream live logs only. Sending history caused duplicate lines when a log
        # was added to the queue while the initial history batch was still being
        # flushed to a freshly connected client.
        loop = asyncio.get_event_loop()
        while True:
            try:
                log = await loop.run_in_executor(None, lambda: scan_state.log_queue.get(timeout=0.5))
                yield f"data: {log}\n\n"
            except queue.Empty:
                with scan_state.lock:
                    if not scan_state.running and scan_state.log_queue.empty():
                        yield "data: [SCAN_COMPLETE]\n\n"
                        break
                await asyncio.sleep(0.5)

    return StreamingResponse(log_generator(), media_type="text/event-stream")


@app.middleware("http")
async def session_and_cache(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # Assign each visitor a private, cookie-keyed sandbox so their edits/scans/deletes
    # never affect other visitors or the owner's baseline.
    sid = request.cookies.get(SESSION_COOKIE)
    is_new = not _valid_sid(sid)
    if is_new:
        sid = uuid.uuid4().hex
    request.state.session_id = sid

    response = await call_next(request)

    if is_new:
        response.set_cookie(SESSION_COOKIE, sid or "", max_age=SESSION_TTL, httponly=True, samesite="lax")
    # Force revalidation of static assets; otherwise browsers heuristically cache
    # app.js/graph-renderer.js and code fixes never reach an open dashboard tab.
    if not request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# Host static files
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
else:

    @app.get("/")
    def read_root() -> dict[str, str]:
        return {"message": "Static folder not found. Please verify the build."}


def run_server(host: str, port: int, config_path: str) -> None:
    global BASELINE_CONFIG
    p = Path(config_path)
    if p.is_absolute():
        BASELINE_CONFIG = p
    else:
        # Check if the path exists relative to the current working directory first,
        # otherwise resolve it relative to the PROJECT_ROOT.
        cwd_p = p.resolve()
        BASELINE_CONFIG = cwd_p if cwd_p.exists() else (PROJECT_ROOT / p).resolve()

    # Warm the shared demo reports in the background so the server starts listening
    # immediately (health checks pass); a very early first visitor just waits on the
    # same one-shot build via _seed_session.
    threading.Thread(target=build_baseline, daemon=True).start()

    import uvicorn

    uvicorn.run(app, host=host, port=port)
