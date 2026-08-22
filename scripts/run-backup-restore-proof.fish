#!/usr/bin/env fish

function docker_compose_restore_proof
    umask 077
    set -l SERVER docker-host
    set -l EXPECTED_SHA256 0b46561cf52c15bfababef0f75fe3bbe2cf1f7e1305eb1f7cfe4c1ca0db5c431
    set -l EXPECTED_BYTES 2319938554
    set -l BACKUP /mnt/storage/backups/daily-local-backup-2026-08-21T22-32-08.tar.gz.gpg

    for tool in gpg python3 ssh shasum
        command -q $tool; or begin
            echo "missing_tool=$tool" >&2
            return 1
        end
    end

    set -l WORKDIR (mktemp -d); or return 1
    set -l VERIFIER "$WORKDIR"/verify-backup-archive.py
    set -l RESTORE_ROOT "$WORKDIR"/restored
    set -l EVIDENCE "$WORKDIR"/restore-evidence.json
    set -l SCRIPT_DIR (path resolve (dirname (status filename)))

    cp "$SCRIPT_DIR"/verify-backup-archive.py "$VERIFIER"; or return 1

    chmod 0755 "$VERIFIER"; or return 1
    python3 -m py_compile "$VERIFIER"; or return 1

    set -l ACTUAL_SHA256 (shasum -a 256 "$VERIFIER" | awk '{print $1}')
    test "$ACTUAL_SHA256" = bdfddde9c07c837341797f639abcdf06bc47334331084038c9b2ee1edd36a60b; or begin
        echo verifier_checksum=failed >&2
        return 1
    end

    set -l RECOVERY_FINGERPRINT 5B14A67EC89DBA1F4C0FEE7CA678E17443DBD7A4
    gpg --batch --with-colons --list-secret-keys "$RECOVERY_FINGERPRINT" 2>/dev/null \
        | string match -q "*:$RECOVERY_FINGERPRINT:*"; or begin
        echo recovery_identity=missing >&2
        return 1
    end

    set -l REMOTE_METADATA (ssh "$SERVER" "sudo -n stat -c '%s' '$BACKUP'; sudo -n sha256sum '$BACKUP' | cut -d' ' -f1"); or return 1
    test (count $REMOTE_METADATA) -eq 2; or return 1
    test "$REMOTE_METADATA[1]" = "$EXPECTED_BYTES"; or begin
        echo ciphertext_size=failed >&2
        return 1
    end
    test "$REMOTE_METADATA[2]" = "$EXPECTED_SHA256"; or begin
        echo ciphertext_checksum=failed >&2
        return 1
    end

    read --silent --prompt-str 'GPG passphrase (input hidden): ' GPG_PASSPHRASE </dev/tty; or return 1
    echo >/dev/tty
    test -n "$GPG_PASSPHRASE"; or begin
        echo gpg_passphrase=empty >&2
        return 1
    end

    echo verifier_checksum=pass
    echo restore_stream=starting
    set -l STARTED (date +%s)

    ssh "$SERVER" "exec sudo -n cat -- '$BACKUP'" \
        | gpg --batch --yes --quiet --pinentry-mode loopback \
            --passphrase-file (printf '%s\n' "$GPG_PASSPHRASE" | psub -f) \
            --decrypt 2>/dev/null \
        | python3 "$VERIFIER" --restore-root "$RESTORE_ROOT" \
        | tee "$EVIDENCE"

    set -l PIPE_RESULTS $pipestatus
    set --erase GPG_PASSPHRASE

    for RESULT in $PIPE_RESULTS
        test "$RESULT" -eq 0; or begin
            if test (path dirname "$RESTORE_ROOT") = "$WORKDIR"
                rm -rf -- "$RESTORE_ROOT"; or return 1
                rm -f -- "$VERIFIER"; or return 1
                test -s "$EVIDENCE"; or rm -f -- "$EVIDENCE"
            end
            echo decrypted_cleanup=pass >&2
            echo restore_pipeline=failed >&2
            return 1
        end
    end

    set -l FINISHED (date +%s)
    chmod 0600 "$EVIDENCE"; or return 1
    test (path dirname "$RESTORE_ROOT") = "$WORKDIR"; or return 1
    rm -rf -- "$RESTORE_ROOT"; or return 1
    rm -f -- "$VERIFIER"; or return 1
    test ! -e "$RESTORE_ROOT"; or return 1
    echo restore_pipeline=pass
    echo restore_elapsed_seconds=(math "$FINISHED" - "$STARTED")
    echo decrypted_cleanup=pass
    echo evidence_file="$EVIDENCE"
end

docker_compose_restore_proof
exit $status
