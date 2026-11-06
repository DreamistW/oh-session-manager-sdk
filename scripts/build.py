"""从已锁定的原生 HAR 编译会话 SDK，并审计最终 HAR。"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from har import build_har, verify_har

ROOT = Path(__file__).resolve().parents[1]
ABI = "arm64-v8a"
LIBRARY = "libsession_manager_core.a"


def stage_dependency(spec: dict, source: Path | None, destination: Path) -> Path:
    """校验固定 Release 字节与包元数据，仅展开头文件和许可。"""
    if source is None:
        source = destination / (spec["name"] + ".har")
        with urllib.request.urlopen(spec["url"], timeout=120) as response, source.open("wb") as output:
            shutil.copyfileobj(response, output)
    with source.open("rb") as archive_file:
        digest = hashlib.file_digest(archive_file, "sha256").hexdigest()
    if digest != spec["sha256"]:
        raise ValueError(f'{spec["name"]} HAR hash differs from dependency lock')
    with tarfile.open(source) as archive:
        metadata = json.load(archive.extractfile("package/oh-package.json5"))
        if (metadata["name"], metadata["version"], metadata["compatibleSdkVersion"]) != (
            spec["name"], spec["version"], 23
        ):
            raise ValueError(f'{spec["name"]} HAR has incompatible metadata')
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if (member.isfile() and len(parts) > 2 and parts[0] == "package"
                    and parts[1] in ("include", "licenses") and ".." not in parts):
                target = destination.joinpath(*parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
    return destination


def native_build(sdk: Path, temporary: Path, ssh: Path, tls: Path) -> Path:
    """用 CLT 交叉编译 SDK 自己的 PIC 对象。"""
    native = sdk / "sdk/default/openharmony/native"
    extension = ".exe" if os.name == "nt" else ""
    cmake = native / ("build-tools/cmake/bin/cmake" + extension)
    ninja = native / ("build-tools/cmake/bin/ninja" + extension)
    toolchain = sdk / "sdk/default/hms/native/build/cmake/hmos.toolchain.cmake"
    build = temporary / "native-build"
    subprocess.run([
        cmake, "-S", ROOT / "native", "-B", build, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja}",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}", f"-DOHOS_SDK_NATIVE={native}",
        f"-DOHOS_ARCH={ABI}", "-DCMAKE_BUILD_TYPE=Release",
        f"-DLIBSSH2_OH_INCLUDE={ssh / 'include'}", f"-DMBEDTLS_OH_INCLUDE={tls / 'include'}",
    ], check=True)
    subprocess.run([cmake, "--build", build, "--parallel"], check=True)
    return build / LIBRARY


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libssh2", type=Path, help="Use a local HAR with the locked hash")
    parser.add_argument("--mbedtls", type=Path, help="Use a local HAR with the locked hash")
    args = parser.parse_args()
    sdk = Path(os.environ["DEVECO_CLI_CLT_PATH"]).resolve(strict=True)
    lock = json.loads((ROOT / "dependencies.lock.json").read_text(encoding="utf-8"))
    module = ROOT / "library"
    builds = ROOT / "build"
    builds.mkdir(exist_ok=True)
    lib_path = f"libs/{ABI}/{LIBRARY}"
    with tempfile.TemporaryDirectory(prefix="session-manager-", dir=builds) as directory:
        temporary = Path(directory)
        ssh, tls = temporary / "libssh2", temporary / "mbedtls"
        ssh.mkdir()
        tls.mkdir()
        stage_dependency(lock["libssh2-oh"], args.libssh2, ssh)
        stage_dependency(lock["mbedtls-oh"], args.mbedtls, tls)
        (module / lib_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(native_build(sdk, temporary, ssh, tls), module / lib_path)
        (module / "licenses").mkdir(exist_ok=True)
        for package, filename in ((ssh, "libssh2-COPYING"), (tls, "MbedTLS-LICENSE.txt")):
            shutil.copyfile(package / "licenses" / filename, module / "licenses" / filename)
    version = json.loads((module / "oh-package.json5").read_text(encoding="utf-8"))["version"]
    files = {name: hashlib.sha256((module / name).read_bytes()).hexdigest()
             for name in (lib_path, "include/session-manager-sdk.h", "include/session-manager-sdk.cmake",
                          "licenses/libssh2-COPYING", "licenses/MbedTLS-LICENSE.txt")}
    manifest = {
        "name": "session-manager-sdk", "version": version,
        "platform": {"minApi": 23, "targetApi": 26, "abi": ABI, "deviceType": "2in1"},
        "dependencies": lock, "files": files,
    }
    manifest_path = "include/session-manager-sdk-manifest.json"
    (module / manifest_path).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    package = build_har(ROOT, sdk, "session_manager_sdk", "session-manager-sdk", version)
    verify_har(package, "session-manager-sdk", version, files, manifest_path)


if __name__ == "__main__":
    main()
