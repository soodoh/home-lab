{ config, lib, pkgs, vm100Projection ? builtins.fromJSON (builtins.readFile ../../vm-100/projection.json), ... }:
let
  dockerEnabled = vm100Projection.deploymentAuthority != "arch";
  artifactHash = lib.removeSuffix "\n" (builtins.readFile ../../compose-artifact.sha256);
  artifact = pkgs.runCommand "vm-100-compose-artifact-${artifactHash}" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    cp -R --no-preserve=mode ${../../compose-artifact} "$out"
    chmod -R u+w "$out"
    actual=$(python3 "$out/scripts/compose-artifact.py" --root "$out" --no-git hash)
    test "$actual" = ${lib.escapeShellArg artifactHash}
    printf '%s\n' ${lib.escapeShellArg artifactHash} > "$out/.artifact-sha256"
  '';
  probeImage = "redis:8.2-m01-alpine@sha256:73785dd3f61435fbea1a14bafd2c6509f9df112f50953e09eb31c94717c77e76";
  qualification = pkgs.writeShellApplication {
    name = "vm-100-compose-qualification";
    runtimeInputs = [ pkgs.coreutils pkgs.docker pkgs.docker-compose pkgs.python3 ];
    text = ''
      work=$(${pkgs.coreutils}/bin/mktemp -d)
      trap '${pkgs.coreutils}/bin/rm -rf "$work"' EXIT
      ${pkgs.python3}/bin/python3 - ${artifact}/secrets/production.env.keys "$work/qualification.env" <<'PY'
      import pathlib, sys
      keys = pathlib.Path(sys.argv[1]).read_text().splitlines()
      path = pathlib.Path(sys.argv[2])
      values = {}
      for key in keys:
          value = "qualification"
          if key == "INTERNAL_HOST_IP": value = "127.0.0.1"
          elif key == "TZ": value = "UTC"
          elif key == "DOMAIN": value = "example.invalid"
          elif key.endswith(("__PORT", "__TIMEOUT")): value = "25"
          elif key.endswith(("__USE_SSL", "__USE_TLS")): value = "false"
          elif key.endswith(("_URL", "_BASE_URL", "_AUTHORITY")): value = "http://127.0.0.1"
          elif key.endswith("_PATH") or key in {"GAMES_PATH", "HASS_PATH", "MEDIA_PATH", "VUETORRENT_PATH"}: value = f"/tmp/vm-100-compose-qualification/{key.lower()}"
          elif key == "RESOLVER_ADDRESS": value = "127.0.0.1"
          elif key == "SERVER_COUNTRIES": value = "US"
          values[key] = value
      path.write_text("".join(f"{key}={values[key]}\\n" for key in keys))
      path.chmod(0o600)
      PY
      ${pkgs.docker}/bin/docker version --format '{{.Server.Version}}' > "$work/docker-version"
      ${pkgs.docker-compose}/bin/docker-compose \
        --project-directory ${artifact} \
        --env-file "$work/qualification.env" \
        config --format json > "$work/model.json"
      ${pkgs.python3}/bin/python3 - "$work/model.json" ${lib.escapeShellArg probeImage} <<'PY'
      import json, pathlib, sys
      model = json.loads(pathlib.Path(sys.argv[1]).read_text())
      services = model.get("services")
      if not isinstance(services, dict) or len(services) != 41:
          raise SystemExit("Compose service inventory differs")
      images = [service.get("image") for service in services.values()]
      if any(not isinstance(image, str) or "@sha256:" not in image for image in images):
          raise SystemExit("Compose image pinning differs")
      if sys.argv[2] not in images:
          raise SystemExit("Compose probe image differs")
      PY
      ${pkgs.docker}/bin/docker pull ${lib.escapeShellArg probeImage} >/dev/null
      ${pkgs.docker}/bin/docker run --rm --network none --read-only --cap-drop ALL \
        ${lib.escapeShellArg probeImage} redis-server --version > "$work/probe"
      printf 'vm-100-compose-qualification=passed services=41 artifact=%s\n' \
        "$(${pkgs.coreutils}/bin/cat ${artifact}/.artifact-sha256)"
    '';
  };
in
{
  options.homeLab.vm100 = {
    composeArtifact = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      internal = true;
    };
    composeQualification = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      internal = true;
    };
  };

  config = {
    homeLab.vm100.composeArtifact = artifact;
    homeLab.vm100.composeQualification = qualification;

    virtualisation.docker = {
      enable = dockerEnabled;
      autoPrune.enable = false;
      daemon.settings = {
        live-restore = true;
        log-driver = "local";
      };
    };

    environment.systemPackages = [ pkgs.docker-compose qualification ];
    environment.etc."home-lab/compose-artifact".source = artifact;
    environment.etc."home-lab/compose-artifact.sha256".text = "${artifactHash}\n";

    assertions = [
      {
        assertion = builtins.match "^[0-9a-f]{64}$" artifactHash != null;
        message = "VM 100 Compose artifact hash must be a lowercase SHA-256 digest";
      }
      {
        assertion = !config.virtualisation.docker.autoPrune.enable;
        message = "VM 100 Docker must not enable unrestricted automatic pruning";
      }
    ];
  };
}
