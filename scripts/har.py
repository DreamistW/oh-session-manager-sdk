"""本机和 GitHub Actions 共用的 HAR 打包、内容检查与校验文件生成。"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile


def build_har(root: Path, sdk: Path, module: str, name: str, version: str) -> Path:
    """使用指定 CLT 生成版本化 HAR。"""
    extension = ".bat" if os.name == "nt" else ""
    subprocess.run([sdk / f"bin/ohpm{extension}", "install", "--all"], cwd=root, check=True)
    if os.name == "nt":
        command = ["devecocli.cmd", "build", "--modules", module, "--assemble-type", "assembleHar",
                   "--build-mode", "release"]
    else:
        command = [sdk / "bin/hvigorw", "assembleHar", "--mode", "module",
                   "-p", f"module={module}@default", "-p", "product=default",
                   "-p", "buildMode=release", "--no-daemon"]
    environment = os.environ.copy()
    environment.pop("DEVECO_CLI_STUDIO_PATH", None)
    subprocess.run(command, cwd=root, env=environment, check=True)
    output = root / "dist" / f"{name}-{version}.har"
    output.parent.mkdir(exist_ok=True)
    shutil.copyfile(root / f"library/build/default/outputs/default/{module}.har", output)
    return output


def verify_har(package: Path, name: str, version: str, expected: dict, manifest: str) -> None:
    """验证最终包内容、最低 API、原生库清单与隐私边界后生成 SHA-256。"""
    sensitive = re.compile(
        rb"(?i)(?:[a-z]:[\\/](?:users|sdk)[\\/]|/(?:home|Users)/[^/\s]+/|"
        rb"192\.168\.\d{1,3}\.\d{1,3}|yume\.w@outlook\.com|"
        rb"-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{32,})"
    )
    with tarfile.open(package) as archive:
        members = archive.getmembers()
        assert len({member.name for member in members}) == len(members), "Duplicate HAR entries"
        for member in members:
            parts = PurePosixPath(member.name).parts
            assert parts and parts[0] == "package" and ".." not in parts, "Unsafe HAR path"
            assert member.isfile() or member.isdir(), "Unexpected special entry in HAR"
            if member.isfile():
                assert not member.name.endswith((".so", ".p12", ".cer", ".p7b", ".keystore")), "Unexpected HAR binary"
                assert sensitive.search(archive.extractfile(member).read()) is None, f"Sensitive content in {member.name}"
        metadata = json.load(archive.extractfile("package/oh-package.json5"))
        assert (metadata["name"], metadata["version"], metadata["compatibleSdkVersion"]) == (name, version, 23)
        assert {m.name.removeprefix("package/") for m in members if m.name.endswith(".a")} == {
            path for path in expected if path.endswith(".a")
        }, "Unexpected static library set"
        report = json.load(archive.extractfile("package/" + manifest))
        assert report["files"] == expected, "HAR manifest differs from input"
        for path, digest in expected.items():
            assert hashlib.sha256(archive.extractfile("package/" + path).read()).hexdigest() == digest, path
        assert any(m.isfile() and "/licenses/" in m.name for m in members), "Missing third-party licenses"
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    package.with_suffix(".har.sha256").write_text(f"{digest}  {package.name}\n", encoding="ascii")
    print(f"HAR_VERIFY_PASS {name}@{version} {digest}")
