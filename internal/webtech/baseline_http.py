"""Compare the complete HTTP suite with the passive hook removed in a shadow workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

EXPECTED = {
    "malformed_input_and_stream_gaps_emit_events": {"test_line":324,"cause":"Preserved orientation/recovery buffers unknown BROKEN request method and returns Ok; historical test expects Error."},
    "unsolicited_response_is_an_event_not_a_record": {"test_line":469,"cause":"Preserved unsolicited-response branch writes the observed HTTP record; historical test expects none."},
    "upgrade_and_connect_leave_http_without_errors": {"test_line":442,"cause":"Preserved map_transaction stores the raw CONNECT target h:443; historical test expects //h:443."},
}

def run(root, env):
    command=["cargo","test","--offline","-p","netcap-applayer","--test","http","--","--test-threads=1"]
    result=subprocess.run(command,cwd=root,env=env,text=True,capture_output=True)
    failures=sorted(re.findall(r"^test ([\w:]+) \.\.\. FAILED$",result.stdout,re.MULTILINE))
    return {"command":command,"returncode":result.returncode,"failures":failures,"stdout":result.stdout,"stderr":result.stderr}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust",type=Path,required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args()
    rust=args.rust.resolve()
    env={**os.environ,"CARGO_TARGET_DIR":str(rust/"target")}
    current=run(rust,env)
    source=(rust/"crates/netcap-applayer/src/http.rs").read_text()
    with tempfile.TemporaryDirectory(prefix="webtech-no-hook-",dir=rust/"target") as directory:
        shadow=Path(directory)
        for name in ["Cargo.toml","Cargo.lock","rust-toolchain.toml","LICENSE"]:
            shutil.copyfile(rust/name,shadow/name)
        for name in ["crates","compat","upstream"]:
            shutil.copytree(rust/name,shadow/name,ignore=shutil.ignore_patterns("target","node_modules",".git","*.pcap","*.pcapng","*.pcap.gz","*.sqlite","*.ncap","*.ncap.gz"))
        no_hook,count=re.subn(r"            crate::http_webtech::observe\(.*?\n            \);\n","",source,count=1,flags=re.DOTALL)
        assert count==1,"passive transaction hook shape changed"
        prefix="    pub fn new() -> Self {\n        Self::with_webtech(crate::http_webtech::snapshot())\n    }\n\n    pub fn with_webtech(webtech: std::sync::Arc<WebtechSnapshot>) -> Self {\n"
        assert prefix in no_hook,"HTTP constructor shape changed"
        no_hook=no_hook.replace(prefix,"    pub fn new() -> Self {\n",1)
        no_hook=no_hook.replace("    webtech: std::sync::Arc<crate::http_webtech::Snapshot>,\n","",1)
        no_hook=no_hook.replace("            webtech,\n","",1)
        (shadow/"crates/netcap-applayer/src/http.rs").write_text(no_hook)
        baseline=run(shadow,env)
    proof={"scope":"shadow copy only; current working files preserved; no captures or user data copied", "current_http_sha256":hashlib.sha256(source.encode()).hexdigest(),"without_hook_http_sha256":hashlib.sha256(no_hook.encode()).hexdigest(),"removed":"passive observe call, webtech snapshot field and constructor initialization; all concurrent HTTP recovery/mapping code retained", "current":current,"without_hook":baseline,"known_failures":EXPECTED,"identical_failure_set":current["failures"]==baseline["failures"]==sorted(EXPECTED)}
    args.receipt.write_text(json.dumps(proof,indent=2)+"\n")
    if not proof["identical_failure_set"]:
        raise SystemExit(f"HTTP failure set differs: current={current['failures']} without-hook={baseline['failures']}; inspect {args.receipt}")
    print(f"HTTP baseline confirmed: same {len(EXPECTED)} failures with and without passive hook; {args.receipt}")

if __name__=="__main__":
    main()
