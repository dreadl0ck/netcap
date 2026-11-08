"""Run owned Go/Rust contracts and write reproducible synthetic-only receipts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(argv, cwd, env):
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, check=True)
    return completed.stdout

def check(argv,cwd,env):
    result=subprocess.run(argv,cwd=cwd,env=env,text=True,capture_output=True)
    return {"command":argv,"returncode":result.returncode,"stdout":result.stdout,"stderr":result.stderr}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    rust = args.rust.resolve()
    env = {**os.environ, "GOWORK":"off", "NETCAP_GEOIP_LIVE_TEST":"0"}
    vectors = HERE / "vectors.json"
    catalogue = HERE / "webtech-descriptors.json"
    assert vectors.read_bytes() == (rust / "crates/netcap-webtech/tests/vectors.json").read_bytes()
    assert catalogue.read_bytes() == (rust / "crates/netcap-webtech/src/webtech-descriptors.json").read_bytes()
    assert (HERE / "NUCLEI-LICENSE.txt").read_bytes() == (rust / "crates/netcap-webtech/NUCLEI-LICENSE.txt").read_bytes()
    assert (HERE / "FIRST-PARTY-LICENSE.txt").read_bytes() == (rust / "crates/netcap-webtech/FIRST-PARTY-LICENSE.txt").read_bytes()
    with tempfile.TemporaryDirectory(prefix="webtech-shared-fixture-",dir=rust/"target") as directory:
        generated=Path(directory)/"optional-catalogues.json"
        run(["go","run","./internal/webtech/cmd/prepare","-test-fixture",str(generated)],ROOT,env)
        assert generated.read_bytes()==(rust/"crates/netcap-webtech/tests/optional-catalogues.json").read_bytes(),"Go/Rust installed fixture drift"
    go = json.loads(run(["go", "run", "./internal/webtech/cmd/qualify", str(vectors), str(catalogue)], ROOT, env))
    rs = json.loads(run(["cargo", "run", "--offline", "--quiet", "-p", "netcap-webtech", "--example", "qualify", "--", str(vectors), str(catalogue)], rust, env))
    assert go == rs, "Go/Rust full-report mismatch"
    service = json.loads((ROOT / "internal/servicesignatures/provenance.json").read_text())
    base = rust / "compat/fixtures/service-signatures"
    for name, entry in [("golden.json", "fixtures"), ("validation.json", "validation")]:
        assert digest(base / name) == service[entry]["sha256"]
        rows = json.loads((base / name).read_text())
        assert [row["name"] for row in rows] == service[entry]["reviewed_names"]
        assert len(rows) == service[entry]["count"]
    proof = rust / "compat/fixtures/w66-release/go-contract.json"
    assert digest(proof) == service["existing_machine_proof"]["sha256"]
    pinned = json.loads(proof.read_text())["source_sha256"]
    for path in ["internal/servicesignatures/engine.go", "internal/servicesignatures/builtin.json"]:
        assert digest(ROOT / path) == pinned[path], "historical service parser/catalogue changed"
    go_tests = check(["go", "test", "-race", "-count=1", "-tags=nodpi,noyara", "./internal/webtech/...", "./internal/servicesignatures", "./internal/decoder/stream/service", "./internal/decoder/stream/http", "./internal/decoder/stream/software"], ROOT, env)
    api_tests=check(["go","test","-race","-count=1","-tags=nodpi,noyara","./cmd/capture/webui","-run=TestCatalogueAttributionFullNoticesAndVerifiedSources"],ROOT,env)
    run(["python3",str(HERE/"baseline_http.py"),"--rust",str(rust),"--receipt",str(HERE/"http-baseline-receipt.json")],rust,env)
    http_baseline=json.loads((HERE/"http-baseline-receipt.json").read_text())
    argv = ["cargo", "test", "--offline", "-p", "netcap-webtech", "-p", "netcap-service-signatures", "-p", "netcap-applayer", "--test", "webtech", "--test", "contract", "--lib"]
    rust_tests = run(argv, rust, env)
    rust_services=run(["cargo","test","--offline","-p","netcap-enrichment","--test","optional_services"],rust,env)
    dependency_clippy=check(["cargo", "clippy", "--offline", "-p", "netcap-webtech", "-p", "netcap-applayer", "-p", "netcap-enrichment", "--lib", "--tests", "--", "-D", "warnings"], rust, env)
    run(["cargo", "clippy", "--offline", "--no-deps", "-p", "netcap-webtech", "-p", "netcap-applayer", "-p", "netcap-enrichment", "--lib", "--tests", "--", "-D", "warnings"], rust, env)
    run(["cargo","check","--offline","-p","netcap-cli"],rust,env)
    benchmark = run(["go", "test", "-run=^$", "-bench=BenchmarkObserve", "-benchmem", "-count=1", "./internal/webtech"], ROOT, env)
    rust_benchmark = json.loads(run(["cargo", "run", "--release", "--offline", "--quiet", "-p", "netcap-webtech", "--example", "benchmark"], rust, env))
    owned_go = list(HERE.rglob("*.go")) + [HERE / p for p in ["provenance.json", "format-contract.json", "NOTICE.txt", "NUCLEI-LICENSE.txt", "FIRST-PARTY-LICENSE.txt", "qualify.py", "baseline_http.py"]] + [ROOT / p for p in ["internal/decoder/stream/http/http.go", "internal/decoder/stream/http/http_reader.go", "internal/decoder/stream/http/webtech_test.go", "internal/decoder/stream/software/webtech.go", "internal/decoder/stream/software/webtech_test.go", "internal/decoder/stream/software/software.go", "internal/decoder/stream/software/software_analysis.go", "internal/decoder/stream/service/service_probe.go", "internal/decoder/stream/service/service_signatures_test.go", "internal/servicesignatures/provenance.json", "cmd/capture/webui/enrichment_attribution.go", "cmd/capture/webui/enrichment_attribution_test.go"]]
    owned_rust = list((rust / "crates/netcap-webtech").rglob("*.rs")) + [rust / p for p in ["crates/netcap-applayer/src/http.rs", "crates/netcap-applayer/src/http_webtech.rs", "crates/netcap-applayer/tests/webtech.rs", "crates/netcap-enrichment/src/services.rs", "crates/netcap-enrichment/tests/optional_services.rs", "crates/netcap-cli/src/capture.rs", "crates/netcap-cli/src/offline_capture.rs"]]
    source_hashes = {"go/" + str(p.relative_to(ROOT)):digest(p) for p in owned_go}
    source_hashes.update({"rust/" + str(p.relative_to(rust)):digest(p) for p in owned_rust})
    receipt = {"qualified_at":datetime.now(timezone.utc).isoformat(), "scope":"local synthetic qualification; no production packets, publication, commits or deployment", "catalogue_sha256":digest(catalogue), "vectors_sha256":digest(vectors), "installed_shared_fixture_sha256":digest(rust/"crates/netcap-webtech/tests/optional-catalogues.json"), "source_sha256":source_hashes, "full_report_differential_cases":len(go), "reports":go, "service_claim_fixtures":14, "service_validation_cases":17, "historical_machine_proof_sha256":digest(proof), "historical_service_parser_and_catalogue_unchanged":True, "historical_whole_database_pin":"known source drift outside service engine/catalogue; existing proof preserved, not regenerated", "go_tests":go_tests, "go_attribution_api_tests":api_tests, "rust_tests":rust_tests, "rust_optional_service_tests":rust_services, "rust_owned_passed":sum(map(int, re.findall(r"test result: ok\. (\d+) passed",rust_tests+rust_services))), "rust_complete_http_passed":False, "rust_complete_http_baseline":http_baseline, "clippy_owned":"passed: --no-deps webtech/applayer/enrichment libraries and tests, -D warnings", "clippy_including_dependencies":dependency_clippy, "cli_check":"passed", "go_benchmark":benchmark, "rust_benchmark":rust_benchmark}
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Qualification recorded: {len(go)} exact reports; Go tests rc={go_tests['returncode']}, Go API rc={api_tests['returncode']}; {receipt['rust_owned_passed']} owned Rust tests passed; complete HTTP suite has {len(http_baseline['current']['failures'])} baseline-confirmed failures; dependency Clippy rc={dependency_clippy['returncode']}; receipt {args.receipt}")

if __name__ == "__main__":
    main()
