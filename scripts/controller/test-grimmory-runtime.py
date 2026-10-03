#!/usr/bin/env python3
"""Opt-in pinned-image qualification; local Docker and synthetic data only.

Run with GRIMMORY_RUNTIME_TEST=1. Creates an isolated Compose project and removes
its synthetic volumes on completion. Never reads SOPS or production app data.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("grimmory_contract", Path(__file__).with_name("test-grimmory.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


@unittest.skipUnless(os.environ.get("GRIMMORY_RUNTIME_TEST") == "1", "explicit local-container qualification required")
class PinnedRuntimeTests(unittest.TestCase):
    run_native = contract.NativeAuthenticationTests.run_native

    def test_native_config_tree_database_uid_and_settings_api(self):
        endpoint = subprocess.run(["docker", "context", "inspect", "--format", "{{ .Endpoints.docker.Host }}"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        self.assertTrue(endpoint.startswith("unix://"), "Refuse a remote Docker qualification target")
        rendered = subprocess.run(["docker", "compose", "config", "--no-interpolate", "--no-env-resolution", "--format", "json"],
                                  cwd=ROOT, capture_output=True, text=True, check=True)
        model = json.loads(rendered.stdout)
        services = {name: copy.deepcopy(model["services"][name]) for name in ("grimmory", "grimmory-db")}
        with tempfile.TemporaryDirectory(prefix=".grimmory-runtime-test-", dir=Path.home()) as directory:
            work = Path(directory)
            # Public images need no persistent registry credentials. Keep the
            # controller's unrelated credential-helper configuration untouched.
            plugins = json.loads(subprocess.run(["docker", "info", "--format", "{{json .ClientInfo.Plugins}}"],
                                                capture_output=True, text=True, check=True).stdout)
            config = work / "docker-config"
            config.mkdir()
            (config / "config.json").write_text(json.dumps({
                "cliPluginsExtraDirs": sorted({str(Path(plugin["Path"]).parent) for plugin in plugins}),
            }))
            environment = {**os.environ, "DOCKER_CONFIG": str(config), "DOCKER_HOST": endpoint}
            environment.pop("DOCKER_CONTEXT", None)
            for service in services.values():
                service.pop("container_name", None)
                service["restart"] = "no"
                service["environment"]["TZ"] = "UTC"
            services["grimmory"]["networks"] = {"application": {}, "database": {}}
            services["grimmory"]["ports"] = ["127.0.0.1::6060"]
            services["grimmory"]["volumes"] = [
                {"type": "volume", "source": "app-data", "target": "/app/data"},
                {"type": "volume", "source": "bookdrop", "target": "/bookdrop"},
                {"type": "volume", "source": "books", "target": "/books", "read_only": True},
                {"type": "volume", "source": "credentials", "target": "/run/secrets", "read_only": True},
            ]
            services["grimmory"]["environment"]["DATABASE_URL"] = "jdbc:mariadb://grimmory-db:3306/grimmory"
            services["grimmory-db"]["networks"] = {"database": {}}
            services["grimmory-db"]["volumes"] = [{"type": "volume", "source": "db-data", "target": "/var/lib/mysql"}]
            services["grimmory"]["secrets"] = []
            services["grimmory-db"]["secrets"] = []
            services["grimmory-db"]["volumes"].append(
                {"type": "volume", "source": "credentials", "target": "/run/secrets", "read_only": True})
            declarations = {item["path"]: item for item in json.loads((ROOT / "services/credentials.json").read_text())["files"]}
            credential_metadata = {name: declarations[model["secrets"][name]["file"]]
                                   for name in ("grimmory_db_password", "grimmory_datasource_password", "grimmory_db_root_password")}
            for name, metadata in credential_metadata.items():
                path = work / name
                path.write_text("synthetic-native-" + metadata["key"])
                path.chmod(0o400)
            project = "grimmory-test-" + uuid.uuid4().hex[:8]
            credential_volume = project + "_credentials"
            holder = project + "-credential-staging"
            credential_targets = (("grimmory_db_password", "grimmory_db_password"),
                                  ("grimmory_datasource_password", "spring.datasource.password"),
                                  ("grimmory_db_root_password", "grimmory_db_root_password"))
            permissions = []
            for source, target in credential_targets:
                metadata = credential_metadata[source]
                permissions.extend([f"chown {metadata['owner']}:{metadata['group']} /run/secrets/{target}",
                                    f"chmod {metadata['mode']} /run/secrets/{target}"])
            document = {"services": services,
                        "volumes": {"app-data": {}, "db-data": {}, "bookdrop": {}, "books": {},
                                    "credentials": {"name": credential_volume}},
                        "networks": {"application": {}, "database": {"internal": True}}}
            path = work / "compose.json"
            path.write_text(json.dumps(document))
            command = ["docker", "compose", "--project-name", project, "-f", str(path)]
            holder_created = False
            try:
                # Native Docker copy works even when a local VM cannot bind the
                # controller's filesystem. All copied bytes are synthetic.
                subprocess.run(["docker", "volume", "create", "--label", "com.docker.compose.project=" + project,
                                "--label", "com.docker.compose.volume=credentials", credential_volume],
                               env=environment, capture_output=True, check=True)
                subprocess.run(["docker", "create", "--name", holder, "--user", "0:0", "--entrypoint", "/bin/sh", "--mount",
                                "type=volume,source=" + credential_volume + ",target=/run/secrets",
                                services["grimmory-db"]["image"], "-ec",
                                "; ".join(permissions)],
                               env=environment, capture_output=True, check=True)
                holder_created = True
                for source, target in credential_targets:
                    subprocess.run(["docker", "cp", str(work / source), holder + ":/run/secrets/" + target],
                                   env=environment, capture_output=True, check=True)
                # Match Linux production ownership/modes, not a permissive macOS
                # bind workaround: the app must read through GID 1000, and the
                # non-root database must read its own password files.
                subprocess.run(["docker", "start", "--attach", holder], env=environment, capture_output=True, check=True)
                subprocess.run(["docker", "rm", holder], env=environment, capture_output=True, check=True)
                holder_created = False
                start = subprocess.run(command + ["up", "-d", "--wait", "--wait-timeout", "240"],
                                       capture_output=True, text=True, timeout=360, env=environment)
                if start.returncode:
                    diagnostics = subprocess.run(command + ["logs", "--no-color", "--tail", "30", "grimmory-db"],
                                                 capture_output=True, text=True, env=environment).stdout
                    for metadata in credential_metadata.values():
                        diagnostics = diagnostics.replace("synthetic-native-" + metadata["key"], "<REDACTED>")
                    self.fail("Pinned synthetic containers did not become healthy: " + start.stderr[-2000:] + diagnostics[-4000:])
                uid = subprocess.run(command + ["exec", "-T", "grimmory-db", "id", "-u"],
                                     capture_output=True, text=True, check=True, env=environment).stdout.strip()
                self.assertEqual(uid, "999")
                subprocess.run(command + ["exec", "-T", "--user", "1000:1000", "grimmory", "sh", "-ec",
                                          "test -r /run/secrets/spring.datasource.password; "
                                          "test ! -r /run/secrets/grimmory_db_root_password"],
                               capture_output=True, check=True, env=environment)
                port = subprocess.run(command + ["port", "grimmory", "6060"], capture_output=True, text=True, check=True, env=environment).stdout.strip()
                self.assertTrue(port.startswith("127.0.0.1:"))
                url = "http://" + port
                with contract.api_server() as (discovery, _):
                    first = self.run_native(url, initialize=True, discovery_url=discovery + "/discovery")
                    self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
                    second = self.run_native(url, discovery_url=discovery + "/discovery")
                    self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
                    self.assertRegex(second.stdout, r"changed=0\s")
                    rotated = self.run_native(url, secret="synthetic-runtime-rotation", discovery_url=discovery + "/discovery")
                    self.assertEqual(rotated.returncode, 0, rotated.stdout + rotated.stderr)
            finally:
                if holder_created:
                    subprocess.run(["docker", "rm", "-f", holder], env=environment, capture_output=True, check=True)
                cleanup = subprocess.run(command + ["down", "--volumes", "--remove-orphans"], capture_output=True, text=True, timeout=60, env=environment)
                self.assertEqual(cleanup.returncode, 0, "Inspect the retained synthetic Compose project after failed cleanup")


if __name__ == "__main__":
    unittest.main()
