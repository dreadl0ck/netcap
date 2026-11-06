import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "zeus/scripts/run-service-container.sh"
ENTRYPOINT = ROOT / "docker/service/entrypoint.sh"
COMPOSE = ROOT / "docker/dbs-server/docker-compose.yml"


class ContainerTrust(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.registry = self.root / "operator reviews.json"
        self.registry.write_text("[]\n")
        self.pin = hashlib.sha256(self.registry.read_bytes()).hexdigest()
        self.log = self.root / "calls.jsonl"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("NC_")}
        self.env.update(
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            HOME=str(self.root),
            CONFIG_DIR=str(self.root / "config"),
            DATA_DIR=str(self.root / "data"),
            NC_CONFIG_ROOT=str(self.root / "config directory"),
            NC_DATA_DIR=str(self.root / "service-data"),
            NC_DBS_APPROVALS=str(self.registry),
            NC_DBS_APPROVALS_SHA256=self.pin,
            TRUST_TEST_LOG=str(self.log),
            OPEN_BROWSER="false",
            FOLLOW_LOGS="false",
        )
        for name in ["docker", "chown", "net"]:
            path = self.bin / name
            path.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "name = Path(sys.argv[0]).name\n"
                "row = {'name': name, 'args': sys.argv[1:]}\n"
                "if name == 'net':\n"
                "    row['registry'] = os.environ.get('NC_DBS_APPROVALS')\n"
                "    row['pin'] = os.environ.get('NC_DBS_APPROVALS_SHA256')\n"
                "with open(os.environ['TRUST_TEST_LOG'], 'a') as f: f.write(json.dumps(row) + '\\n')\n"
                "if name == 'net' and sys.argv[1:2] == ['util'] and os.environ.get('TRUST_TEST_DOWNLOAD_FAIL'): sys.exit(1)\n"
            )
            path.chmod(0o700)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_script(self, path, env=None):
        return subprocess.run(
            ["bash" if path == LAUNCHER else "sh", str(path)],
            env=self.env if env is None else env,
            text=True, capture_output=True, timeout=15,
        )

    def test_missing_or_invalid_trust_fails_before_docker_or_net(self):
        for script in [LAUNCHER, ENTRYPOINT]:
            for change, name in [
                ({"NC_DBS_APPROVALS": ""}, "NC_DBS_APPROVALS"),
                ({"NC_DBS_APPROVALS": str(self.root)}, "NC_DBS_APPROVALS"),
                ({"NC_DBS_APPROVALS_SHA256": ""}, "NC_DBS_APPROVALS_SHA256"),
                ({"NC_DBS_APPROVALS_SHA256": "invalid"}, "NC_DBS_APPROVALS_SHA256"),
                ({"NC_DBS_APPROVALS_SHA256": "0" * 64}, "digest mismatch"),
            ]:
                with self.subTest(script=script.name, change=list(change)):
                    result = self.run_script(script, self.env | change)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(name, result.stderr)
                    self.assertEqual(self.calls(), [])
                    self.assertNotIn(self.pin, result.stdout + result.stderr)

    def test_launcher_forwards_only_the_registry_file_read_only_and_supplied_pin(self):
        result = self.run_script(LAUNCHER)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(c["args"] for c in self.calls() if c["name"] == "docker" and c["args"][0] == "run")
        self.assertEqual(args[args.index("--mount") + 1], f"type=bind,source={self.registry},target=/run/netcap-trust/approvals.json,readonly")
        self.assertIn("NC_DBS_APPROVALS=/run/netcap-trust/approvals.json", args)
        self.assertIn("NC_DBS_APPROVALS_SHA256=" + self.pin, args)
        self.assertNotIn(self.pin, result.stdout + result.stderr)

    def test_existing_mounted_release_still_requires_trust(self):
        dbs = Path(self.env["NC_CONFIG_ROOT"]) / "dbs"
        dbs.mkdir(parents=True)
        (dbs / ".release.json").write_text('{"synthetic":"mounted marker"}')
        for script in [LAUNCHER, ENTRYPOINT]:
            result = self.run_script(script, self.env | {"NC_DBS_APPROVALS_SHA256": ""})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("NC_DBS_APPROVALS_SHA256", result.stderr)
            self.assertEqual(self.calls(), [])
        result = self.run_script(ENTRYPOINT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c["args"][0] for c in self.calls()], ["capture"])

    def test_download_receives_trust_and_failure_does_not_start_service(self):
        result = self.run_script(ENTRYPOINT, self.env | {"TRUST_TEST_DOWNLOAD_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        calls = self.calls()
        self.assertEqual([c["args"] for c in calls], [["util", "-download-dbs"]])
        self.assertEqual(calls[0]["registry"], str(self.registry))
        self.assertEqual(calls[0]["pin"], self.pin)
        self.assertIn("Reviewed database download failed", result.stderr)

    def test_successful_bootstrap_starts_service(self):
        result = self.run_script(ENTRYPOINT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c["args"][0] for c in self.calls()], ["util", "capture"])

    def test_default_community_bootstrap_needs_no_operator_mount(self):
        env = self.env | {"NC_DBS_APPROVALS": "", "NC_DBS_APPROVALS_SHA256": ""}
        result = self.run_script(ENTRYPOINT, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c["args"][0] for c in self.calls()], ["util", "capture"])
        self.log.unlink()
        result = self.run_script(LAUNCHER, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(c["args"] for c in self.calls() if c["name"] == "docker" and c["args"][0] == "run")
        self.assertNotIn("--mount", args)
        self.assertFalse(any("NC_DBS_APPROVALS" in a for a in args))

    def test_symlink_registry_is_rejected(self):
        alias = self.root / "alias.json"
        alias.symlink_to(self.registry)
        for script in [LAUNCHER, ENTRYPOINT]:
            result = self.run_script(script, self.env | {"NC_DBS_APPROVALS": str(alias)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [])

    def test_compose_requires_explicit_trust_and_narrow_read_only_bind(self):
        docker = shutil.which("docker", path=os.environ["PATH"])
        if not docker or subprocess.run([docker, "compose", "version"], capture_output=True).returncode:
            self.skipTest("Docker Compose is unavailable")
        command = [docker, "compose", "-f", str(COMPOSE), "config", "--format", "json"]
        for name in ["NC_DBS_APPROVALS", "NC_DBS_APPROVALS_SHA256"]:
            env = self.env.copy()
            env[name] = ""
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(name, result.stderr)
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        service = json.loads(result.stdout)["services"]["netcap-dbs-server"]
        binds = [v for v in service["volumes"] if v["type"] == "bind"]
        self.assertEqual(len(binds), 1)
        self.assertEqual(binds[0]["source"], str(self.registry))
        self.assertEqual(binds[0]["target"], "/run/netcap-trust/approvals.json")
        self.assertTrue(binds[0]["read_only"])
        self.assertFalse(binds[0]["bind"]["create_host_path"])
        self.assertEqual(service["environment"]["NC_DBS_APPROVALS"], binds[0]["target"])
        self.assertEqual(service["environment"]["NC_DBS_APPROVALS_SHA256"], self.pin)


if __name__ == "__main__":
    unittest.main()
