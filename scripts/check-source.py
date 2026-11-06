"""审查 Git 发布输入，报告路径和规则类别，避免回显私密值。"""
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_DIRECTORIES = {
    ".cache", ".cxx", ".hvigor", ".idea", "artifacts", "build", "dist",
    "node_modules", "oh_modules", "prebuilt", "signing", "__pycache__",
}
FORBIDDEN_SUFFIXES = {".a", ".so", ".har", ".hap", ".cer", ".csr", ".p12", ".p7b", ".pem", ".jks", ".keystore"}
FORBIDDEN_NAMES = {".env", ".ohpmrc", "local.properties", "lab.json", "secrets.env"}
RULES = {
    "private address": rb"(?<![0-9])(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?![0-9])",
    "personal email": rb"(?i)[a-z0-9_.%+-]+@(?:outlook|hotmail|gmail)\.com",
    "local path": rb"(?i)(?:[a-z]:[\\/](?:users|sdk)[\\/]|/(?:home|Users)/[^/\s]+/)",
    "private key": rb"-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{32,}",
    "GitHub token": rb"(?:gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,})",
}

listed = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode("utf-8").split("\0")
for filename in filter(None, listed):
    path = PurePosixPath(filename)
    if (FORBIDDEN_DIRECTORIES.intersection(path.parts) or path.suffix in FORBIDDEN_SUFFIXES
            or path.name in FORBIDDEN_NAMES):
        raise SystemExit(f"Excluded release input: {filename}")
    source = ROOT / filename
    if source.is_symlink():
        raise SystemExit(f"Unexpected link: {filename}")
    data = source.read_bytes()
    for rule, expression in RULES.items():
        if re.search(expression, data):
            raise SystemExit(f"Sensitive release input ({rule}): {filename}")
    if b"signingConfigs" in data and filename.endswith("build-profile.json5"):
        if re.search(rb'"signingConfigs"\s*:\s*\[\s*\]', data) is None:
            raise SystemExit(f"Nonempty signing configuration: {filename}")
print("PUBLIC_SOURCE_AUDIT_PASS")
