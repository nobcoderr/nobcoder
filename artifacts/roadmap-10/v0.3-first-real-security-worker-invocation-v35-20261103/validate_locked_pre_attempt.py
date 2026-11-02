"""Execute the exact locked V26 entrypoint through the pre-attempt boundary only."""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
RUN=ROOT/"static-run-v35"

def main()->int:
    completed=subprocess.run(
        ["/usr/bin/python3.14","-B",str(ROOT/"src/runner_v35.py"),"--mode","validate-pre-attempt"],
        cwd=ROOT,env={"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","PYTHONDONTWRITEBYTECODE":"1","PYTHONHASHSEED":"0"},text=True,check=False,
    )
    summary_path=RUN/"LOCKED_PRE_ATTEMPT_VALIDATION_RESULT.json"
    summary=json.loads(summary_path.read_text()) if summary_path.is_file() else {}
    ok=(completed.returncode==0 and summary.get("status")=="PASS"
        and summary.get("stopped_before_attempt_marker") is True
        and summary.get("observer_ready") is True and summary.get("tracer_ready") is True
        and not (RUN/"ATTEMPT_MARKER.json").exists()
        and not (RUN/"runtime-result-0001.json").exists()
        and summary.get("attempt_count")==summary.get("worker_invocation_count")==summary.get("codex_as_worker_invocation_count")==0)
    print(json.dumps({"status":"PASS" if ok else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "entrypoint_exit":completed.returncode,"attempt_count":0,"worker_invocation_count":0,
        "codex_as_worker_invocation_count":0},sort_keys=True))
    return 0 if ok else 1
if __name__=="__main__": raise SystemExit(main())
