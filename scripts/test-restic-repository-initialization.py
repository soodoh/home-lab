#!/usr/bin/env python3
"""Focused safety fixtures for owner-bound Restic repository initialization."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/initialize-restic-repositories"

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(mode)

def main() -> None:
    source = HELPER.read_text()
    assert 'ACTIONS = {"initialize", "resume", "verify"}' in source
    assert 'OPERATION = "restic-repository-initialization"' in source
    assert '"/usr/sbin/runuser", "--user", "restic-proton"' in source
    assert "PROTON_ID = 60000" in source
    assert 'os.getgrouplist("restic-proton", service.pw_gid)' in source
    assert "sorted(set(groups)) != [PROTON_ID]" in source
    assert "--copy-chunker-params" in source
    assert "safe_games_permissions" in source
    assert "unadoptable_repository_" in source
    assert "stderr_sha256_" in source
    assert not any(term in source for term in ['"sync"', '"bisync"', '"purge"', '"cleanup"', '"mount"'])
    resume_playbook = (ROOT / "ansible/playbooks/resume-restic-repository-initialization.yml").read_text()
    assert "restic_repository_exclusive_client_confirmation" in resume_playbook
    assert "backups.restic.initialization.exclusive_client_confirmation" in resume_playbook
    assert "current_object_retention_days >= 365" in resume_playbook
    assert "migration_retention_hold.review_deadline > now" in resume_playbook
    namespace = runpy.run_path(str(HELPER))
    with tempfile.TemporaryDirectory() as tree_directory:
        os.environ["HOME_LAB_RESTIC_INITIALIZATION_TESTING"] = "1"
        os.environ["HOME_LAB_RESTIC_INITIALIZATION_TEST_ROOT"] = tree_directory
        tree = Path(tree_directory) / "repository"
        tree.mkdir()
        first = tree / "first"; first.write_bytes(b"fixture")
        second = tree / "second"; os.link(first, second)
        try:
            namespace["validate_local_tree"](tree, "fixture")
            raise AssertionError("hard-linked repository tree passed")
        except namespace["InitializationError"] as error:
            assert str(error) == "fixture_repository_tree"
        second.unlink(); (tree / "link").symlink_to(first)
        try:
            namespace["validate_local_tree"](tree, "fixture")
            raise AssertionError("symlinked repository tree passed")
        except namespace["InitializationError"] as error:
            assert str(error) == "fixture_repository_tree"

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        installed_helper = root / "usr/local/libexec/home-lab/initialize-restic-repositories"
        write(installed_helper, HELPER.read_bytes(), 0o750)
        remote_config = root / "fake-proton-config.json"
        restic = root / "usr/local/bin/restic"
        restic_script = f'''#!/usr/bin/env python3
import json,pathlib,sys
if sys.argv[1:] == ["version"]:
 print("restic fixture")
 raise SystemExit
repo=sys.argv[sys.argv.index("-r")+1]
args=sys.argv[sys.argv.index("-r")+2:]
path=pathlib.Path({str(remote_config)!r}) if repo.startswith("rclone:") else pathlib.Path(repo)/"config"
if args[0] == "init":
 path.parent.mkdir(parents=True,exist_ok=True)
 source = None
 if "--from-repo" in args:
  source=pathlib.Path(args[args.index("--from-repo")+1])/"config"
 polynomial=json.loads(source.read_text())["chunker_polynomial"] if source else "1234abcd"
 identifier=("a" if "/mnt/games/restic/home-lab" in repo else "b" if "/mnt/storage/restic/home-lab" in repo else "c")*64
 path.write_text(json.dumps({{"version":2,"id":identifier,"chunker_polynomial":polynomial}}))
 path.chmod(0o600)
elif args == ["cat","config"]:
 print(path.read_text())
else:
 raise SystemExit(2)
'''.encode()
        write(restic, restic_script, 0o755)
        rclone = root / "usr/local/bin/rclone"
        rclone_script = f'''#!/usr/bin/env python3
import json,pathlib,sys
if sys.argv[1:] == ["version"]:
 print("rclone fixture")
elif sys.argv[1] == "about":
 print(json.dumps({{"total":1073741824000,"free":1073741824000,"used":0}}))
elif sys.argv[1] == "lsjson":
 if pathlib.Path({str(remote_config)!r}).exists(): print(json.dumps({{"Path":"Backups/home-lab-restic","IsDir":True}}))
 else: raise SystemExit(3)
else:
 raise SystemExit(2)
'''.encode()
        write(rclone, rclone_script, 0o755)
        rendered = subprocess.run(["node", "-e", "const fs=require('fs'),y=require('js-yaml'); process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8')).backups.restic))", str(ROOT / "infrastructure/contract/home-lab.yml")], capture_output=True, text=True, check=True)
        policy = json.loads(rendered.stdout)
        policy["initialization"].update({"state": "ready", "source_policy_sha256": None, "evidence_sha256": None, "verified_at": None})
        for repository in policy["repositories"].values():
            repository["id"] = None
        policy["tools"]["restic"]["installed_sha256"] = digest(restic_script)
        policy["tools"]["restic"]["version_output"] = "restic fixture"
        policy["tools"]["rclone"]["installed_sha256"] = digest(rclone_script)
        policy["tools"]["rclone"]["version_output_prefix"] = "rclone fixture"
        policy["initialization"]["helper_sha256"] = digest(HELPER.read_bytes())
        username = "fixture-user"
        policy["qualification"]["username_sha256"] = digest(username.encode())
        qualification = b'{"fixture":"qualified"}\n'
        policy["qualification"]["evidence_sha256"] = digest(qualification)
        write(root / "var/lib/home-lab-restic/proton-qualification.json", qualification, 0o600)
        write(root / "etc/home-lab/restic/credentials/local-password", b"l" * 40 + b"\n", 0o440)
        write(root / "etc/home-lab/restic/credentials/proton-password", b"p" * 40 + b"\n", 0o440)
        config = f"[proton-backup]\ntype = protondrive\nusername = {username}\npassword = obscured\nreplace_existing_draft = true\nenable_caching = true\noriginal_file_size = true\n".encode()
        write(root / "var/lib/restic-proton/rclone.conf", config, 0o600)
        (root / "var/lib/restic-proton/cache").mkdir(parents=True)
        (root / "var/cache/home-lab-restic").mkdir(parents=True)
        (root / "mnt/games/restic").mkdir(parents=True)
        (root / "mnt/storage/restic").mkdir(parents=True)
        owner = b"controller=ansible-deploy\noperation=restic-repository-initialization\nstarted=2026-08-26T01:00:00Z\n"
        write(root / "var/lib/iac-ansible-production.lock/owner", owner, 0o600)
        policy_path = root / "etc/home-lab/restic-policy.json"
        raw_policy = (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode()
        write(policy_path, raw_policy, 0o440)
        env = {**os.environ, "HOME_LAB_RESTIC_INITIALIZATION_TESTING": "1", "HOME_LAB_RESTIC_INITIALIZATION_TEST_ROOT": str(root)}
        (root / "mnt/games/restic").chmod(0o777)
        unsafe_parent = subprocess.run([str(HELPER), "initialize"], env=env, text=True, capture_output=True)
        assert unsafe_parent.returncode == 1 and "repository_parent_games" in unsafe_parent.stderr
        (root / "mnt/games/restic").chmod(0o750)
        initial = subprocess.run([str(HELPER), "initialize"], env=env, text=True, capture_output=True, check=True)
        assert initial.stdout.startswith("restic_repository_initialization=passed evidence_sha256=")
        result_path = root / policy["initialization"]["result_path"].lstrip("/")
        evidence_path = root / policy["initialization"]["host_evidence_path"].lstrip("/")
        assert result_path.read_bytes() == evidence_path.read_bytes()
        evidence_raw = evidence_path.read_bytes()
        evidence = json.loads(evidence_raw)
        assert len(set(evidence["repository_ids"].values())) == 3
        assert evidence["operations"] == ["init-games", "init-nfs-from-games-copy-chunker-params", "normalize-games-access", "init-proton-from-games-copy-chunker-params"]
        journal_path = root / policy["initialization"]["journal_path"].lstrip("/")
        journal = json.loads(journal_path.read_text())
        assert journal["phase"] == "complete"
        assert journal["completed_at"] == evidence["completed_at"]
        original_result = result_path.read_bytes()
        original_evidence = evidence_path.read_bytes()
        original_hash = digest(original_evidence)
        malformed_complete = json.loads(json.dumps(journal))
        malformed_complete["completed_at"] = None
        write(journal_path, (json.dumps(malformed_complete, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
        malformed_replay = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert malformed_replay.returncode == 1 and "journal_completed_at" in malformed_replay.stderr
        write(journal_path, (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
        replayed = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert replayed.returncode == 0, replayed.stderr
        assert result_path.read_bytes() == original_result
        assert evidence_path.read_bytes() == original_evidence
        assert digest(evidence_path.read_bytes()) == original_hash

        write(result_path, b"{}\n", 0o600)
        mismatch = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert mismatch.returncode == 1 and "retained_evidence_mismatch" in mismatch.stderr
        result_path.unlink()
        result_path.symlink_to(root / "missing-retained-evidence")
        unsafe_output = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert unsafe_output.returncode == 1 and "protected_file_type" in unsafe_output.stderr
        result_path.unlink()
        write(result_path, original_result, 0o600)

        premarker = json.loads(json.dumps(journal))
        premarker["phase"] = "nfs_initialized"
        premarker.pop("completed_at")
        premarker["repositories"].pop("proton")
        write(journal_path, (json.dumps(premarker, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
        premarker_replay = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert premarker_replay.returncode == 1 and "repository_target_exists_proton" in premarker_replay.stderr

        adoptable = json.loads(json.dumps(premarker))
        adoptable["phase"] = "proton_init_started"
        write(journal_path, (json.dumps(adoptable, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
        cached_config = config + b"client_uid = uid\nclient_access_token = access\nclient_refresh_token = refresh\nclient_salted_key_pass = salted\n"
        write(root / "var/lib/restic-proton/rclone.conf", cached_config, 0o600)
        result_path.unlink(); evidence_path.unlink()
        resumed = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert resumed.returncode == 0, resumed.stderr
        assert "initialization=passed" in resumed.stdout
        evidence_raw = evidence_path.read_bytes(); evidence = json.loads(evidence_raw)
        stable_result = result_path.read_bytes(); stable_evidence = evidence_path.read_bytes()
        stable_replay = subprocess.run([str(HELPER), "resume"], env=env, text=True, capture_output=True)
        assert stable_replay.returncode == 0, stable_replay.stderr
        assert result_path.read_bytes() == stable_result
        assert evidence_path.read_bytes() == stable_evidence
        policy["initialization"].update({"state":"initialized", "source_policy_sha256":evidence["source_policy_sha256"], "evidence_sha256":digest(evidence_raw), "verified_at":evidence["completed_at"]})
        for name, identifier in evidence["repository_ids"].items(): policy["repositories"][name]["id"] = identifier
        write(policy_path, (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o440)
        verified = subprocess.run([str(HELPER), "verify"], env=env, text=True, capture_output=True, check=True)
        assert "initialization=verified" in verified.stdout
        policy["repositories"]["proton"]["id"] = "d" * 64
        write(policy_path, (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o440)
        rejected = subprocess.run([str(HELPER), "verify"], env=env, text=True, capture_output=True)
        assert rejected.returncode == 1 and "repository_contract_identity" in rejected.stderr

    print("restic repository initialization safety fixtures passed")

if __name__ == "__main__":
    main()
