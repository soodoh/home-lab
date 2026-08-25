#!/usr/bin/env python3
"""Static interruption-boundary tests for Proton qualification transactions."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def ordered(content: str, names: list[str]) -> None:
    positions = [content.index(name) for name in names]
    assert positions == sorted(positions), f"transaction order differs: {names}"


def main() -> None:
    qualification = (ROOT / "ansible/playbooks/qualify-proton-backup.yml").read_text()
    recovery = (ROOT / "ansible/playbooks/recover-proton-qualification.yml").read_text()
    resume = (ROOT / "ansible/playbooks/resume-proton-qualification.yml").read_text()

    ordered(
        qualification,
        [
            "Run the bounded Proton qualification under the shared backup mutex",
            "Publish root-owned Proton qualification evidence on the host",
            "Fetch bounded Proton qualification evidence for reviewed attestation",
            "Remove only the transient user-owned qualification result",
            "Release the shared production mutation lock after verified qualification",
        ],
    )
    ordered(
        recovery,
        [
            "Require exact password-only deployment evidence for recovery",
            "Recover only exact qualification fixtures under the backup mutex",
            "Retain root-owned failed qualification recovery evidence",
            "Remove only the transient qualification recovery result",
            "Release only the verified failed Proton qualification lock",
        ],
    )
    ordered(
        resume,
        [
            "Inspect all possible interrupted transaction evidence sources",
            "Require all retained evidence sources to be byte-identical",
            "Verify the dedicated remote qualification directory is absent",
            "Publish missing root-owned qualification evidence",
            "Fetch completed qualification evidence for reviewed attestation",
            "Remove only the validated transient result when present",
            "Release only the resumed Proton qualification lock",
        ],
    )

    assert "['transient', 'qualification']" in resume
    assert "['transient', 'recovery']" in resume
    assert "Require strict completed qualification evidence for qualification resume" in resume
    assert "Require strict completed recovery evidence for recovery resume" in resume
    assert "proton_qualification_remote=absent" in resume
    assert "attest-interrupted-proton-qualification" in resume
    assert "attest-interrupted-proton-recovery" in resume
    assert "proton-qualification-recovery-{{ proton_resume_transaction_sha256 }}.json" in resume
    assert "evidence.transaction_sha256 == proton_resume_transaction_sha256" in resume

    old_transaction = "a" * 64
    current_transaction = "b" * 64
    files = {f"proton-qualification-recovery-{old_transaction}.json"}
    current_recovery_name = f"proton-qualification-recovery-{current_transaction}.json"
    current_sources = {"proton-qualification-result.json", current_recovery_name} & files
    assert current_sources == set(), "stale recovery evidence was accepted for a newer lock"
    assert "state: absent" in resume

    helper = (ROOT / "scripts/qualify-proton-backup").read_text()
    assert '{"inspect", "qualify", "recover"}' in helper
    assert "qualification_remote_not_absent" in helper
    assert 'print("proton_qualification_remote=absent")' in helper
    assert '"transaction_sha256": transaction_sha256' in helper

    print("proton transaction interruption fixtures passed")


if __name__ == "__main__":
    main()
