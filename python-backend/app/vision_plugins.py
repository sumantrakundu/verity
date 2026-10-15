"""Optional local adapters for research image-forensics model runners.

Runners are separate user-installed scripts because DocTamper/TruFor require
their own compatible runtimes and model weights. See README for the JSON API.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path


def run_local_screening_model(name: str, data: bytes, extension: str) -> dict:
    env_key = f"VERITY_{name.upper()}_RUNNER"
    runner_value = os.getenv(env_key, "").strip()
    if not runner_value:
        return {"available": False, "status": "Not Checked", "message": f"{name} runner and model weights are not configured."}
    runner = Path(runner_value).expanduser().resolve()
    if not runner.is_file():
        return {"available": False, "status": "Not Checked", "message": f"Configured {name} runner path does not exist."}

    try:
        with tempfile.TemporaryDirectory(prefix="verity-model-") as temp:
            work = Path(temp)
            image_path = work / ("input" + (extension if extension in {".jpg", ".jpeg", ".png"} else ".img"))
            result_path = work / "result.json"
            image_path.write_bytes(data)
            python_exe = os.getenv(f"VERITY_{name.upper()}_PYTHON", sys.executable)
            if not Path(python_exe).is_file() and not shutil.which(python_exe):
                return {"available": False, "status": "Not Checked", "message": f"Configured {name} Python environment was not found."}
            try:
                timeout = max(30, min(900, int(os.getenv("VERITY_MODEL_TIMEOUT_SECONDS", "300"))))
            except ValueError:
                timeout = 300
            completed = subprocess.run(
                [python_exe, str(runner), "--input", str(image_path), "--output-json", str(result_path)],
                cwd=str(work), capture_output=True, timeout=timeout, check=False,
            )
            if completed.returncode != 0 or not result_path.is_file():
                return {"available": False, "status": "Not Checked", "message": f"{name} runner did not return a usable result."}
            raw = json.loads(result_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not isinstance(raw.get("anomaly_detected"), bool):
                return {"available": False, "status": "Not Checked", "message": f"{name} result did not match the required output format."}
            score = raw.get("screening_score")
            if not isinstance(score, (int, float)) or not 0 <= float(score) <= 1:
                score = None
            regions = []
            for region in raw.get("regions", [])[:20] if isinstance(raw.get("regions", []), list) else []:
                if not isinstance(region, dict):
                    continue
                try:
                    x, y, w, h = (float(region[k]) for k in ("x", "y", "width", "height"))
                except (KeyError, TypeError, ValueError):
                    continue
                if 0 <= x <= 100 and 0 <= y <= 100 and 0 < w <= 100 and 0 < h <= 100:
                    regions.append({"x_percent": x, "y_percent": y, "width_percent": w, "height_percent": h})
            return {
                "available": True,
                "status": "Warning" if raw["anomaly_detected"] else "Passed",
                "anomaly_detected": raw["anomaly_detected"],
                "screening_score": float(score) if score is not None else None,
                "regions": regions,
                "message": str(raw.get("message") or ("The model flagged a potential anomaly; review the highlighted region." if raw["anomaly_detected"] else "The model did not flag a strong anomaly; this does not prove authenticity."))[:500],
            }
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        return {"available": False, "status": "Not Checked", "message": f"{name} screening could not complete; check its local runner and model setup."}
