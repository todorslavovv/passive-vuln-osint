from __future__ import annotations

import asyncio
import json
import logging
import queue
import re
import threading
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..config import TargetConfig, load_targets
from ..logger import logger
from ..pipeline import Pipeline

app = FastAPI(title="OSINT Dependency Intelligence Dashboard")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONFIG_PATH_GLOBAL = Path("examples/targets.json")
OUTPUT_DIR_GLOBAL = Path("reports")


class ScanState:
    def __init__(self) -> None:
        self.running = False
        self.targets: list[str] = []
        self.options: dict[str, Any] = {}
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.history_logs: list[str] = []
        self.error: str | None = None
        self.lock = threading.Lock()


scan_state = ScanState()


class QueueLogHandler(logging.Handler):
    def __init__(self, state: ScanState) -> None:
        super().__init__()
        self.state = state
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        self.state.log_queue.put(msg)
        with self.state.lock:
            self.state.history_logs.append(msg)


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
        mode = "PUBLIC OSINT TARGETS"
        
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
            if len(parts) >= 2:
                if parts[0] == "www":
                    name = parts[1]
                else:
                    name = parts[0]
            else:
                name = hostname or "web-target"
                
        # Clean target name of unsafe chars
        name = re.sub(r"[^a-zA-Z0-9_-]", "-", name).lower()
        if not name:
            name = "target"
            
        return {
            "name": name,
            "url": url_val,
            "mode": mode,
            "github_repos": github_repos,
            "sbom_urls": [],
            "container_images": [],
            "mobile_artifacts": [],
            "package_hints": [],
            "metadata": {}
        }
    except Exception as e:
        raise ValueError(f"Failed to parse target URL: {e}") from e


@app.get("/api/targets")
def get_targets() -> list[dict[str, Any]]:
    try:
        targets = load_targets(CONFIG_PATH_GLOBAL)
        return [t.to_dict() for t in targets]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/targets")
def add_target(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        url = payload.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Target URL is required")
            
        parsed_payload = parse_url_to_target(url)
        targets = load_targets(CONFIG_PATH_GLOBAL)
        
        if any(t.name == parsed_payload["name"] for t in targets):
            raise HTTPException(status_code=400, detail=f"Target '{parsed_payload['name']}' already exists")
            
        new_target = TargetConfig.from_dict(parsed_payload)
        targets.append(new_target)
        save_targets_file(targets)
        return {"status": "success", "target": new_target.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.put("/api/targets/{name}")
def update_target(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        url = payload.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Target URL is required")
            
        parsed_payload = parse_url_to_target(url)
        targets = load_targets(CONFIG_PATH_GLOBAL)
        
        index = -1
        for i, t in enumerate(targets):
            if t.name == name:
                index = i
                break
        if index == -1:
            raise HTTPException(status_code=404, detail=f"Target '{name}' not found")
            
        updated_target = TargetConfig.from_dict(parsed_payload)
        targets[index] = updated_target
        save_targets_file(targets)
        return {"status": "success", "target": updated_target.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.delete("/api/targets/{name}")
def delete_target(name: str) -> dict[str, str]:
    try:
        targets = load_targets(CONFIG_PATH_GLOBAL)
        filtered = [t for t in targets if t.name != name]
        if len(filtered) == len(targets):
            raise HTTPException(status_code=404, detail=f"Target '{name}' not found")
        save_targets_file(filtered)
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


def save_targets_file(targets: list[TargetConfig]) -> None:
    with CONFIG_PATH_GLOBAL.open("w", encoding="utf-8") as f:
        json.dump({"targets": [t.to_dict() for t in targets]}, f, indent=2)


@app.get("/api/reports")
def list_reports() -> list[dict[str, Any]]:
    try:
        if not OUTPUT_DIR_GLOBAL.exists():
            return []
        reports = []
        for file in OUTPUT_DIR_GLOBAL.glob("*.json"):
            if file.name == "aggregate_report.json":
                continue
            try:
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
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
def get_report_detail(target_name: str) -> dict[str, Any]:
    report_file = OUTPUT_DIR_GLOBAL / f"{target_name}.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report for target '{target_name}' not found")
    try:
        with report_file.open("r", encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports/aggregate")
def get_aggregate_report() -> dict[str, Any]:
    report_file = OUTPUT_DIR_GLOBAL / "aggregate_report.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Aggregate report not found")
    try:
        with report_file.open("r", encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/reports/nvidia-summary")
def get_nvidia_summary() -> dict[str, str]:
    summary_file = OUTPUT_DIR_GLOBAL / "nvidia_human_summary.txt"
    if not summary_file.exists():
        raise HTTPException(status_code=404, detail="NVIDIA summary file not found")
    try:
        return {"summary": summary_file.read_text(encoding="utf-8")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/scans/status")
def get_scan_status() -> dict[str, Any]:
    with scan_state.lock:
        return {
            "running": scan_state.running,
            "targets": scan_state.targets,
            "options": scan_state.options,
            "error": scan_state.error,
        }


def run_scan_thread(targets_to_scan: list[str], options: dict[str, Any]) -> None:
    global scan_state

    handler = QueueLogHandler(scan_state)
    logger.addHandler(handler)

    logger.info("Web scan run initiated. Targets: %s", ", ".join(targets_to_scan))
    try:
        all_targets = load_targets(CONFIG_PATH_GLOBAL)
        selected_targets = [t for t in all_targets if t.name in targets_to_scan]
        if not selected_targets:
            raise ValueError("No matching targets found to scan")

        offline = options.get("offline", False)
        skip_nvd = options.get("skip_nvd", False)
        nvidia_summary = options.get("nvidia_summary", False)
        rate_limit = options.get("rate_limit", 4.0)
        max_enrich_dependencies = options.get("max_enrich_dependencies")

        output_dir = Path(options.get("output_dir", str(OUTPUT_DIR_GLOBAL)))

        pipeline = Pipeline(
            offline=offline,
            fixture_path=None,
            max_enrichment_dependencies=max_enrich_dependencies,
            enable_nvd=not skip_nvd,
            rate_limit_rps=rate_limit,
        )

        result = pipeline.process_targets(selected_targets, output_dir=output_dir, include_graph=True)

        if nvidia_summary:
            import os

            api_key = os.environ.get("NVIDIA_API_KEY")
            if not api_key:
                logger.warning("NVIDIA summary requested but NVIDIA_API_KEY environment variable is missing")
            else:
                from ..ai_summary import write_nvidia_summary

                nvidia_model = options.get("nvidia_model", "nvidia/nemotron-3-ultra-550b-a55b")
                logger.info("Requesting NVIDIA summary using model '%s'...", nvidia_model)
                write_nvidia_summary(result["aggregate"], output_dir, api_key, nvidia_model)
                logger.info("NVIDIA summary complete.")

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
def start_scan(payload: dict[str, Any]) -> dict[str, str]:
    global scan_state

    with scan_state.lock:
        if scan_state.running:
            raise HTTPException(status_code=400, detail="A scan is already running")

        targets_to_scan = payload.get("targets", [])
        if not targets_to_scan:
            raise HTTPException(status_code=400, detail="Must specify targets to scan")

        scan_state.running = True
        scan_state.targets = targets_to_scan
        scan_state.options = payload.get("options", {})
        scan_state.error = None
        scan_state.log_queue = queue.Queue()
        scan_state.history_logs = []

    threading.Thread(target=run_scan_thread, args=(targets_to_scan, scan_state.options), daemon=True).start()

    return {"status": "started"}


@app.get("/api/scans/stream-logs")
def stream_logs() -> StreamingResponse:
    async def log_generator() -> AsyncGenerator[str, None]:
        # First send any history
        with scan_state.lock:
            for log in scan_state.history_logs:
                yield f"data: {log}\n\n"

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


# Host static files
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
else:

    @app.get("/")
    def read_root() -> dict[str, str]:
        return {"message": "Static folder not found. Please verify the build."}


def run_server(host: str, port: int, config_path: str) -> None:
    global CONFIG_PATH_GLOBAL
    CONFIG_PATH_GLOBAL = Path(config_path)

    import uvicorn

    uvicorn.run(app, host=host, port=port)
