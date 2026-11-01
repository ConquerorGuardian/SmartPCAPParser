"""Финальная проверка проекта перед публикацией.

Запуск: python tools/final_check.py

Проверяет то, что легко забыть перед релизом: версию в одном месте, ссылки
в документации, обязательные файлы, отсутствие секретов и крупных файлов в
git, чистоту рабочей папки. В конце печатает итог и код возврата.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures: list[str] = []
checks = 0

REQUIRED = [
    "LICENSE", "CHANGELOG.md", "README.md", "README.en.md",
    "CONTRIBUTING.md", "SECURITY.md",
    "requirements.txt", "requirements-dev.txt", "run.bat", "pyproject.toml",
    ".gitignore", ".gitattributes",
    ".github/workflows/tests.yml", ".github/workflows/build.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "assets/app.ico",
    "docs/FAQ.md", "docs/EXAMPLES.md",
    "tools/build_exe.py", "tools/check_exe.py", "tools/publish.ps1",
    "tools/backup.py", "tools/make_icon.py", "tools/bench.py",
    "tools/make_release_folder.py", "tools/make_friend_kit.py",
    "tests/run_all.py", "tests/sample_traffic.pcap", "tests/sample_traffic.pcapng",
]

DOCS = [
    "README.md", "README.en.md", "CHANGELOG.md", "CONTRIBUTING.md",
    "SECURITY.md", "docs/FAQ.md", "docs/EXAMPLES.md",
]

IMAGES = [
    "docs/screenshot.png", "docs/stats.png", "docs/details.png",
    "docs/stream.png", "docs/theme-light.png", "docs/verdict.png",
]

SECRET_PATTERNS = [
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
]

SKIP_PARTS = {".git", "dist", "build", "backups", ".pylibs", ".tmp",
              ".ruff_cache", "__pycache__", "release", "samples"}
SKIP_SUFFIXES = {".png", ".ico", ".pcap", ".pcapng", ".zip", ".exe", ".gz",
                 ".bundle", ".pdf"}


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print("PASS  {}".format(name))
    else:
        print("FAIL  {} {}".format(name, detail))
        failures.append(name)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_version() -> None:
    import main as entry
    import parser

    version = parser.__version__
    check("версия похожа на SemVer", bool(re.fullmatch(r"\d+\.\d+\.\d+", version)), version)
    check("main.app_version() совпадает", entry.app_version() == version, entry.app_version())
    check("CHANGELOG содержит текущую версию",
          "## [{}]".format(version) in read(ROOT / "CHANGELOG.md"))
    check("pyproject берёт версию из parser",
          'version = { attr = "parser.__version__" }' in read(ROOT / "pyproject.toml"))


def check_files() -> None:
    for item in REQUIRED:
        check("есть {}".format(item), (ROOT / item).exists())
    for image in IMAGES:
        check("картинка {}".format(image), (ROOT / image).exists())


def check_links() -> None:
    for doc in DOCS:
        path = ROOT / doc
        if not path.exists():
            continue
        text = read(path)
        missing = []
        for target in re.findall(r"\]\(([^)#]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:", "#", "../../")):
                continue
            clean = target.split("#")[0].strip()
            if not clean:
                continue
            if not (path.parent / clean).exists():
                missing.append(clean)
        check("ссылки в {} рабочие".format(doc), not missing, str(missing))


def check_requirements() -> None:
    lines = [line for line in read(ROOT / "requirements.txt").lower().splitlines()
             if line.strip() and not line.strip().startswith("#")]
    check("в runtime-зависимостях только customtkinter",
          len(lines) == 1 and lines[0].startswith("customtkinter"), str(lines))


def check_secrets() -> None:
    found = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, text):
                found.append("{}: {}".format(path.relative_to(ROOT), pattern))
    check("в файлах нет токенов и ключей", not found, str(found))


def check_git() -> None:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                              text=True).stdout

    status = git("status", "--porcelain").strip()
    check("рабочая папка чистая", not status, status[:200])

    large = []
    for item in git("ls-files").splitlines():
        path = ROOT / item
        if path.exists() and path.stat().st_size > 2 * 1024 * 1024:
            large.append("{} ({:.1f} МБ)".format(item, path.stat().st_size / 1024 / 1024))
    check("в git нет файлов больше 2 МБ", not large, str(large))

    tracked = set(git("ls-files").splitlines())
    for junk in ("dist/SmartPCAPParser.exe", "build/", "backups/", "internal/"):
        check("{} не в git".format(junk), not any(t.startswith(junk) for t in tracked))


def main() -> int:
    print("Проверка проекта Smart PCAP Parser\n")
    check_version()
    check_files()
    check_links()
    check_requirements()
    check_secrets()
    check_git()

    print("\n" + "-" * 40)
    print("Проверок: {} | провалов: {}".format(checks, len(failures)))
    if failures:
        print("ПРОВАЛЫ: " + ", ".join(failures))
        return 1
    print("Всё в порядке.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
