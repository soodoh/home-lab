#!/usr/bin/env python3
"""Exercise the Compose model and native Ansible file-rendering behavior.

Only synthetic values are used. The local sandbox substitutes the current UID/GID
for privileged host ownership; production reader permissions remain in the model.
"""

import configparser
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import tarfile
import io

import yaml

ROOT = Path(__file__).resolve().parents[2]
BINDINGS = json.loads((ROOT / "services/credentials.json").read_text())


def model():
    result = subprocess.run(
        ["docker", "compose", "config", "--no-env-resolution", "--no-interpolate", "--format", "json"],
        cwd=ROOT, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


class ComposeDelivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = model()

    def test_every_secret_has_a_single_declared_file_authority_and_consumer(self):
        declared = self.model["secrets"]
        paths = {item["path"] for item in BINDINGS["files"]}
        self.assertEqual(len(paths), len(BINDINGS["files"]))
        self.assertEqual({v["file"] for v in declared.values()}, paths - {"/etc/docker-compose/credentials/cli-proxy-api-config.yaml"})
        granted = {s["source"] for service in self.model["services"].values() for s in service.get("secrets", [])}
        self.assertEqual(granted, set(declared))
        for item in BINDINGS["files"]:
            self.assertEqual(item["owner"], "0")
            self.assertEqual(int(item["mode"], 8) & 0o007, 0)
        for service in self.model["services"].values():
            for volume in service.get("volumes", []):
                self.assertNotEqual(volume.get("source"), "/etc/docker-compose/credentials")

    def test_only_declared_interpolation_inputs_and_openfit_credentials_remain(self):
        serialized = json.dumps(self.model)
        referenced = set(re.findall(r"(?<!\$)\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)", serialized))
        self.assertEqual(referenced, set(BINDINGS["environment_keys"]) | {"VAULTWARDEN_SSO_CLIENT_ID"})
        raw_keys = {item["key"] for item in BINDINGS["files"] if "key" in item}
        self.assertFalse(referenced & raw_keys)
        for secret in ("TRAEFIK_TAILNET_AWS_ACCESS_KEY_ID", "TRAEFIK_TAILNET_AWS_SECRET_ACCESS_KEY", "ZWAVE_SECRET"):
            self.assertNotIn(secret, referenced)
        self.assertEqual(self.model["services"]["openfit"]["environment"]["BETTER_AUTH_SECRET"], "$OPENFIT_SECRET")
        self.assertEqual(self.model["services"]["openfit"]["environment"]["ADMIN_PASSWORD"], "$OPENFIT_ADMIN_PASSWORD")

    def test_native_reader_configuration_and_least_privilege_grants(self):
        services = self.model["services"]
        cloud = services["mindwtr-cloud"]
        self.assertEqual(cloud["user"], "0:0")
        self.assertNotIn("MINDWTR_CLOUD_AUTH_TOKENS", cloud["environment"])
        self.assertEqual(cloud["environment"]["MINDWTR_CLOUD_AUTH_TOKENS_FILE"], "/run/secrets/mindwtr_cloud_tokens")
        self.assertEqual([s["source"] for s in cloud["secrets"]], ["mindwtr_cloud_tokens"])
        for name in ("nextcloud", "nextcloud-cron"):
            self.assertEqual(services[name]["environment"]["SMTP_PASSWORD_FILE"], "/run/secrets/nextcloud_smtp_password")
            self.assertNotIn("SMTP_PASSWORD", services[name]["environment"])
            self.assertIn("nextcloud_smtp_password", [s["source"] for s in services[name]["secrets"]])
        for name in ("authentik-server", "authentik-worker"):
            self.assertEqual(services[name]["environment"]["AUTHENTIK_POSTGRESQL__PASSWORD"], "file:///run/secrets/authentik_db_password")
        for secret in services["frigate"]["secrets"]:
            self.assertTrue(secret["source"].startswith("FRIGATE_"))
            self.assertEqual("/run/secrets/" + secret["source"], secret["target"])
        self.assertEqual(services["zwave"]["secrets"][0]["target"], "/usr/src/app/store/.session-secret")
        self.assertNotIn("SESSION_SECRET", services["zwave"]["environment"])
        self.assertEqual(services["recyclarr"]["secrets"][0]["target"], "/config/secrets.yml")
        private = services["traefik-tailnet"]
        self.assertEqual(private["environment"]["AWS_SHARED_CREDENTIALS_FILE"], "/run/secrets/traefik_tailnet_aws_credentials")
        self.assertNotIn("AWS_ACCESS_KEY_ID", private["environment"])
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", private["environment"])
        self.assertNotIn("secrets", services["traefik"])
        gluetun = services["gluetun"]
        self.assertEqual(gluetun["environment"]["VPN_TYPE"], "wireguard")
        self.assertEqual(gluetun["environment"]["PORT_FORWARD_ONLY"], "on")
        for name in ("private_key", "addresses"):
            self.assertEqual(gluetun["environment"]["WIREGUARD_" + name.upper() + "_SECRETFILE"],
                             "/run/secrets/wireguard_" + name)
            self.assertNotIn("WIREGUARD_" + name.upper(), gluetun["environment"])
        self.assertEqual(gluetun["environment"]["MAM_ID_FILE"], "/run/secrets/mam_initial_id")
        self.assertNotIn("MAM_ID", gluetun["environment"])
        self.assertEqual([name for name, service in services.items()
                          if any(s["source"] == "mam_initial_id" for s in service.get("secrets", []))], ["gluetun"])

    def test_recyclarr_uses_read_only_configuration_and_writable_native_state(self):
        service = self.model["services"]["recyclarr"]
        volumes = {v["target"]: v for v in service["volumes"]}
        self.assertFalse(volumes["/config"].get("read_only", False))
        for directory in ("configs", "includes"):
            mount = volumes["/config/" + directory]
            self.assertTrue(mount["read_only"])
            self.assertEqual(Path(mount["source"]), ROOT / "services/data/recyclarr" / directory)
            host_source = "/srv/docker-compose/current/" + str(Path(mount["source"]).relative_to(ROOT))
            self.assertIn(host_source, (ROOT / "services/data/restic/files-from").read_text().splitlines())
            self.assertIn(host_source, json.loads((ROOT / "recovery/groups.json").read_text())["groups"]["media"]["paths"])
        self.assertNotIn("entrypoint", service)
        self.assertEqual(service["secrets"][0]["target"], "/config/secrets.yml")

    def test_backup_and_every_recovery_group_include_the_credential_directory(self):
        backed_up = (ROOT / "services/data/restic/files-from").read_text().splitlines()
        common = json.loads((ROOT / "recovery/groups.json").read_text())["common_paths"]
        self.assertIn("/etc/docker-compose/credentials", backed_up)
        self.assertIn("/etc/docker-compose/credentials", common)
        for item in BINDINGS["files"]:
            self.assertTrue(item["path"].startswith("/etc/docker-compose/credentials/"))


class NativeFileRendering(unittest.TestCase):
    def test_native_archive_extraction_protects_source_and_preserves_executables(self):
        tar_version = subprocess.run(["tar", "--version"], capture_output=True).stdout
        if b"GNU tar" not in tar_version:
            self.skipTest("Native unarchive qualification requires GNU tar (executed on Linux CI)")
        with tempfile.TemporaryDirectory(prefix="compose-source-permission-test-") as directory:
            work = Path(directory)
            archive = work / "source.tar"
            with tarfile.open(archive, "w") as output:
                for name, mode in [("credentials.json", 0o664), ("hook.sh", 0o775)]:
                    item = tarfile.TarInfo(name)
                    item.mode = mode
                    content = b"synthetic source\n"
                    item.size = len(content)
                    output.addfile(item, io.BytesIO(content))
            target = work / "source"
            target.mkdir(mode=0o755)
            deploy = yaml.safe_load((ROOT / "ansible/roles/compose_native/tasks/deploy.yml").read_text())
            block = next(t["block"] for t in deploy if t["name"] == "Archive and converge committed Compose source")
            prepare = next(t["block"] for t in block if t["name"] == "Prepare changed source without publishing it")
            task = copy.deepcopy(next(t for t in prepare if t["name"] == "Extract committed Compose source"))
            task["become"] = False
            task["ansible.builtin.unarchive"].update(src=str(archive), dest=str(target), owner=str(os.getuid()), group=str(os.getgid()))
            playbook = [{"name": "Test native source permissions", "hosts": "localhost", "gather_facts": False,
                "vars": {"ansible_become": False, "ansible_python_interpreter": shutil.which("python3")}, "tasks": [task]}]
            path = work / "play.yml"
            path.write_text(yaml.safe_dump(playbook, sort_keys=False))
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)],
                env={**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg")}, cwd=ROOT, capture_output=True)
            self.assertEqual(result.returncode, 0, "Synthetic native source extraction failed: " + (result.stdout + result.stderr).decode())
            self.assertEqual((target / "credentials.json").stat().st_mode & 0o777, 0o644)
            self.assertEqual((target / "hook.sh").stat().st_mode & 0o777, 0o755)

    def test_exact_values_serialization_permissions_idempotency_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory(prefix="native-credential-test-") as directory:
            work = Path(directory)
            uid, gid = str(os.getuid()), str(os.getgid())
            credentials = copy.deepcopy(BINDINGS)
            for item in credentials["files"]:
                item.update(path=str(work / Path(item["path"]).name), owner=uid, group=gid)
            production = {key: "synthetic-" + key for key in credentials["environment_keys"]}
            production.update({item["key"]: 'synthetic-$value-"quoted"-\\tail' for item in credentials["files"] if "key" in item and item["key"] not in {"VAULTWARDEN_SSO_CLIENT_SECRET", "MAM_INITIAL_ID"}})
            production["TRAEFIK_TAILNET_AWS_ACCESS_KEY_ID"] = "ASYNTHETICKEY12345678"
            production["TRAEFIK_TAILNET_AWS_SECRET_ACCESS_KEY"] = "SyntheticKey/With+Base64=Characters12345678"
            tasks = yaml.safe_load((ROOT / "ansible/roles/compose_native/tasks/credentials.yml").read_text())[1:]
            # Mock only the authority lookup and sandbox privileged environment-file ownership.
            tasks[-1]["ansible.builtin.copy"].update(owner=uid, group=gid)
            tasks.append({"name": "Expose only the recreation decision", "ansible.builtin.debug": {"msg": "credential_files_changed={{ compose_native_credentials_changed }}"}})
            tasks_path = work / "tasks.yml"
            tasks_path.write_text(yaml.safe_dump(tasks, sort_keys=False))
            environment_path = work / "production.env"
            playbook = [{
                "name": "Exercise native credential rendering", "hosts": "localhost", "gather_facts": False,
                "vars": {
                    "ansible_become": False,
                    "ansible_python_interpreter": shutil.which("python3"),
                    "compose_native_controller_root": str(ROOT),
                    "compose_native_credentials": credentials,
                    "compose_native_oidc_secrets": {"schemaVersion": 2, "oauthProviders": {"47": {"client_secret": "s" * 64}}},
                    "compose_native_oidc_desired": {"oauthProviders": {"47": {"client_id": "synthetic-id"}}},
                    "compose_native_cli_proxy_secrets": {"API_KEY": 'synthetic-"api"', "MANAGEMENT_KEY": "synthetic-$management"},
                    "compose_native_runtime_env_path": str(environment_path),
                },
                "tasks": [
                    {"name": "Provide only synthetic authority input", "ansible.builtin.set_fact": {
                        "compose_native_production_secrets": "{{ test_source_values }}",
                        "compose_native_production_dotenv": "{{ test_source_dotenv }}",
                        "compose_native_servarr_secrets": "{{ test_servarr_values }}"}, "no_log": True},
                    {"name": "Run native file tasks", "ansible.builtin.include_tasks": str(tasks_path)},
                ],
            }]
            playbook_path = work / "playbook.yml"
            playbook_path.write_text(yaml.safe_dump(playbook, sort_keys=False))
            variable_path = work / "input.json"

            def render(values, mam_id="synthetic-mam-id", expected_status=0):
                variable_path.write_text(json.dumps({
                    "test_source_values": values,
                    "test_servarr_values": {"indexers": {"8": {"mamId": mam_id}}},
                    "test_source_dotenv": "".join(key + "=" + json.dumps(value) + "\n" for key, value in values.items()),
                }))
                environment = os.environ.copy()
                environment.update(ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_LOCAL_TEMP=str(work / "ansible"), ANSIBLE_NOCOLOR="1")
                result = subprocess.run(
                    ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook_path), "-e", "@" + str(variable_path)],
                    cwd=ROOT, env=environment, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected_status, "Synthetic native Ansible rendering failed: " + result.stdout + result.stderr)
                return result.stdout

            first = render(production)
            self.assertIn("credential_files_changed=True", first)
            for item in credentials["files"]:
                path = Path(item["path"])
                self.assertEqual(path.stat().st_mode & 0o777, int(item["mode"], 8))
                if "key" in item:
                    expected = {"VAULTWARDEN_SSO_CLIENT_SECRET": "s" * 64,
                                "MAM_INITIAL_ID": "synthetic-mam-id"}.get(item["key"], production.get(item["key"]))
                    self.assertEqual(path.read_bytes(), expected.encode())
            aws = configparser.ConfigParser()
            aws.read(work / "traefik-tailnet-aws-credentials")
            self.assertEqual(aws["default"]["aws_access_key_id"], production["TRAEFIK_TAILNET_AWS_ACCESS_KEY_ID"])
            self.assertEqual(aws["default"]["aws_secret_access_key"], production["TRAEFIK_TAILNET_AWS_SECRET_ACCESS_KEY"])
            recyclarr = yaml.safe_load((work / "recyclarr-secrets.yml").read_text())
            for key in ("SONARR_API_KEY", "RADARR_API_KEY", "RADARR_4K_API_KEY"):
                self.assertEqual(recyclarr[key], production[key])
            cli = yaml.safe_load((work / "cli-proxy-api-config.yaml").read_text())
            self.assertEqual(cli["api-keys"], ['synthetic-"api"'])
            self.assertEqual(cli["remote-management"]["secret-key"], "synthetic-$management")
            kept = {line.split("=", 1)[0] for line in environment_path.read_text().splitlines()}
            self.assertEqual(kept, set(BINDINGS["environment_keys"]) | {"VAULTWARDEN_SSO_CLIENT_ID"})
            self.assertEqual(environment_path.stat().st_mode & 0o777, 0o600)
            second = render(production)
            self.assertIn("credential_files_changed=False", second)
            self.assertRegex(second, r"changed=0\s")
            raw_path = work / "sonarr-api-key"
            inode = raw_path.stat().st_ino
            production["SONARR_API_KEY"] = "synthetic-replacement"
            third = render(production)
            self.assertIn("credential_files_changed=True", third)
            self.assertEqual(raw_path.read_text(), "synthetic-replacement")
            self.assertNotEqual(raw_path.stat().st_ino, inode)
            mam_path = work / "mam-initial-id"
            inode = mam_path.stat().st_ino
            rotated = render(production, mam_id="replacement-mam-id")
            self.assertIn("credential_files_changed=True", rotated)
            self.assertEqual(mam_path.read_text(), "replacement-mam-id")
            self.assertNotEqual(mam_path.stat().st_ino, inode)
            for invalid in ["", "bad\nid", "bad\tid", "mam_id=wrong-format"]:
                render(production, mam_id=invalid, expected_status=2)
                self.assertEqual(mam_path.read_text(), "replacement-mam-id")
            for duplicate in ["MAM_ID", "MAM_INITIAL_ID"]:
                render({**production, duplicate: "duplicate-id"}, expected_status=2)
                self.assertEqual(mam_path.read_text(), "replacement-mam-id")
            # Unsafe existing file metadata must be refused before any rewriting.
            raw_path.chmod(0o644)
            variable_path.write_text(json.dumps({"test_source_values": production,
                "test_servarr_values": {"indexers": {"8": {"mamId": "replacement-mam-id"}}},
                "test_source_dotenv": "".join(k + "=" + json.dumps(v) + "\n" for k, v in production.items())}))
            refused = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook_path), "-e", "@" + str(variable_path)],
                cwd=ROOT, env={**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"), "ANSIBLE_NOCOLOR": "1"}, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(raw_path.stat().st_mode & 0o777, 0o644)


class NativeMindwtrReader(unittest.TestCase):
    def test_official_entrypoint_drops_privileges_and_preserves_token_namespace(self):
        image = model()["services"]["mindwtr-cloud"]["image"]
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode:
            self.skipTest("Pinned Mindwtr image is not cached; native reader test requires Docker")
        with tempfile.TemporaryDirectory(prefix="native-mindwtr-test-", dir=Path.home()) as directory:
            path = Path(directory) / "tokens"
            path.write_text("synthetic-token-alpha,synthetic-token-beta")
            path.chmod(0o400)
            script = r'''
                import { resolveAllowedAuthTokensFromEnv, tokenToKey, isAuthorizedToken } from "/app/apps/cloud/src/server-auth.ts";
                if (process.getuid() !== 1000) throw new Error("upstream privilege drop failed");
                const filePath = process.env.MINDWTR_CLOUD_AUTH_TOKENS_FILE;
                const expected = "synthetic-token-alpha,synthetic-token-beta";
                if (await Bun.file(filePath).text() !== expected) throw new Error("token bytes changed");
                const fromFile = resolveAllowedAuthTokensFromEnv(process.env);
                const fromInline = resolveAllowedAuthTokensFromEnv({MINDWTR_CLOUD_AUTH_TOKENS: expected});
                if (JSON.stringify([...fromFile.keys].sort()) !== JSON.stringify([...fromInline.keys].sort())) {
                    throw new Error("authorized tokens changed");
                }
                for (const token of expected.split(",")) {
                    if (!isAuthorizedToken(token, fromFile) || !fromFile.keys.has(tokenToKey(token))) {
                        throw new Error("data namespace changed");
                    }
                }
                if (isAuthorizedToken("synthetic-token-denied", fromFile)) throw new Error("unexpected token accepted");
            '''
            created = subprocess.run([
                "docker", "create", "--network", "none", "--user", "0:0",
                "--env", "MINDWTR_CLOUD_AUTH_TOKENS_FILE=/tmp/source-tokens",
                image, "bun", "--eval", script,
            ], capture_output=True, text=True, check=True)
            container = created.stdout.strip()
            try:
                subprocess.run(["docker", "cp", str(path), container + ":/tmp/source-tokens"], capture_output=True, check=True)
                result = subprocess.run(["docker", "start", "--attach", container], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, "Synthetic native Mindwtr reader failed: " + result.stderr)
                state = subprocess.run(["docker", "inspect", "--format", "{{.State.ExitCode}}", container], capture_output=True, text=True, check=True)
                self.assertEqual(state.stdout.strip(), "0")
            finally:
                subprocess.run(["docker", "rm", "--force", container], capture_output=True, check=True)


class NativeRuntimePaths(unittest.TestCase):
    def test_initialization_preserves_certificates_and_refuses_unsafe_paths(self):
        with tempfile.TemporaryDirectory(prefix="compose-runtime-test-") as directory:
            work = Path(directory)
            store = work / "store"
            certificate = store / "acme.json"
            paths = [
                {"path": str(store), "kind": "directory", "uid": os.getuid(), "gid": os.getgid(), "mode": "0700"},
                {"path": str(certificate), "kind": "file", "uid": os.getuid(), "gid": os.getgid(), "mode": "0600"},
            ]
            playbook = work / "play.json"

            def run(expected=True, check=False):
                playbook.write_text(json.dumps([{
                    "hosts": "localhost", "gather_facts": False,
                    "vars": {"ansible_become": False, "ansible_python_interpreter": shutil.which("python3"),
                             "compose_native_runtime_paths": paths},
                    "tasks": [{"ansible.builtin.include_role": {"name": "compose_native", "tasks_from": "runtime-paths"}}],
                }]))
                args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)]
                if check:
                    args.append("--check")
                result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                    env={**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg")}, timeout=60)
                self.assertEqual(result.returncode == 0, expected, result.stdout + result.stderr)
                self.assertNotIn("synthetic-private-certificate", result.stdout + result.stderr)
                return result.stdout

            run(check=True)
            self.assertFalse(store.exists())
            run()
            self.assertEqual(certificate.read_text(), "{}\n")
            self.assertEqual(store.stat().st_mode & 0o777, 0o700)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o600)
            certificate.write_text("synthetic-private-certificate")
            inode = certificate.stat().st_ino
            self.assertRegex(run(), r"changed=0\s")
            self.assertEqual(certificate.stat().st_ino, inode)
            self.assertEqual(certificate.read_text(), "synthetic-private-certificate")

            # Admission must fail before creating any other declared path.
            additional = {"path": str(work / "untouched"), "kind": "directory", "uid": os.getuid(),
                          "gid": os.getgid(), "mode": "0700"}
            paths.insert(0, additional)
            for field in ("uid", "gid"):
                paths[-1][field] += 1
                run(expected=False)
                paths[-1][field] -= 1
                self.assertFalse((work / "untouched").exists())
            certificate.chmod(0o644)
            run(expected=False)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o644)
            certificate.chmod(0o600)
            certificate.unlink()
            certificate.symlink_to(work / "absent")
            run(expected=False)
            self.assertTrue(certificate.is_symlink())
            self.assertFalse((work / "absent").exists())
            certificate.unlink()
            certificate.mkdir(mode=0o700)
            run(expected=False)
            self.assertTrue(certificate.is_dir())
            self.assertFalse((work / "untouched").exists())


if __name__ == "__main__":
    unittest.main()
