{ lib, stdenv, fetchFromGitHub, kernel, kmod }:
stdenv.mkDerivation (finalAttrs: {
  pname = "gasket-driver";
  version = "r236.5815ee3";

  src = fetchFromGitHub {
    owner = "google";
    repo = "gasket-driver";
    rev = "5815ee3908a46a415aac616ac7b9aedcb98a504c";
    hash = "sha256-O17+msok1fY5tdX1DvqYVw6plkUDF25i8sqwd6mxYf8=";
  };

  patches = [
    ./0001-linux-6.13-dma-buf-namespace.patch
    ./0002-linux-6.0-remove-no-llseek.patch
    ./0003-linux-7.1-zap-special-vma.patch
  ];

  nativeBuildInputs = kernel.moduleBuildDependencies ++ [ kmod ];

  makeFlags = [
    "-C"
    "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "M=$(PWD)/src"
  ];

  buildPhase = ''
    runHook preBuild
    make "''${makeFlags[@]}" modules
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    moduleRoot="$out/lib/modules/${kernel.modDirVersion}/extra"
    install -d "$moduleRoot"
    install -m 0644 src/gasket.ko src/apex.ko "$moduleRoot/"

    for module in gasket apex; do
      test -s "$moduleRoot/$module.ko"
      test "$(modinfo -F vermagic "$moduleRoot/$module.ko" | cut -d' ' -f1)" = "${kernel.modDirVersion}"
      modinfo -F srcversion "$moduleRoot/$module.ko" | grep -Eq '^[0-9A-F]+$'
    done

    install -Dm0644 /dev/null "$out/share/home-lab-coral/build-metadata"
    cat >"$out/share/home-lab-coral/build-metadata" <<EOF
source_commit=5815ee3908a46a415aac616ac7b9aedcb98a504c
kernel_mod_dir_version=${kernel.modDirVersion}
modules=apex,gasket
patches=0001-linux-6.13-dma-buf-namespace.patch,0002-linux-6.0-remove-no-llseek.patch,0003-linux-7.1-zap-special-vma.patch
EOF
    runHook postInstall
  '';

  meta = {
    description = "Pinned Google Gasket and Apex kernel modules for Coral PCIe accelerators";
    homepage = "https://github.com/google/gasket-driver";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
  };
})
