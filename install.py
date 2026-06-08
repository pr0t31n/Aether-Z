#!/usr/bin/env python3
# install.py — Aether-Z ZigBee Penetration Test Orchestrator
# VERSION: 1.0.0 (referenced from /Users/pr0t31n/Aether-Z/VERSION — do not bump here)
# Installs all dependencies for aether_z.py and configures the system.

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"


def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")


def phase_header(title: str) -> None:
    bar = "=" * 60
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)


def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)
def step(msg: str)    -> None: cprint(f"  --> {msg}", CYAN)


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info: dict = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or \
                "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0


def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Package lists
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "python3-pip",
    "python3-dev",
    "git",
    "libusb-1.0-0-dev",
    "build-essential",
    "pkg-config",
    "wireshark",
    "tshark",
    "openocd",
    "binwalk",
    "libpcap-dev",
]

DNF_PACKAGES = [
    "epel-release",
    "python3-pip",
    "python3-devel",
    "git",
    "libusbx-devel",
    "gcc",
    "gcc-c++",
    "make",
    "wireshark",
    "wireshark-cli",
    "openocd",
    "binwalk",
    "libpcap-devel",
]

ZYPPER_PACKAGES = [
    "python3-pip",
    "python3-devel",
    "git",
    "libusb-1_0-devel",
    "gcc",
    "make",
    "wireshark",
    "openocd",
    "libpcap-devel",
]

BREW_PACKAGES = [
    "libusb",
    "wireshark",
    "binwalk",
    "openocd",
]


# ---------------------------------------------------------------------------
# Phase 1 — System packages
# ---------------------------------------------------------------------------

def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists...")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info("Upgrading installed packages...")
    run(["apt-get", "upgrade", "-y"], check=True, dry_run=dry_run)
    info(f"Installing: {' '.join(APT_PACKAGES)}")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)
    # wireshark non-interactive: allow non-root capture
    if not dry_run:
        run(["bash", "-c",
             "echo 'wireshark-common wireshark-common/install-setuid boolean true'"
             " | debconf-set-selections"],
            dry_run=dry_run)
    success("APT phase complete.")


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    run(["dnf", "install", "-y", "epel-release"], dry_run=dry_run)
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(DNF_PACKAGES)}")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)
    warn("binwalk may need manual install on RHEL: pip3 install binwalk")
    success("DNF phase complete.")


def phase_zypper(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (zypper)")
    require_root()
    run(["zypper", "refresh"], dry_run=dry_run)
    run(["zypper", "update", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(ZYPPER_PACKAGES)}")
    run(["zypper", "install", "-y"] + ZYPPER_PACKAGES, check=True, dry_run=dry_run)
    success("Zypper phase complete.")


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")
    warn("macOS: ZigBee hardware interface support via USB requires CP2102/FTDI drivers.")
    warn("KillerBee tools require Linux for full functionality.")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            warn("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    info(f"Installing brew packages: {' '.join(BREW_PACKAGES)}")
    run(base_cmd + ["install"] + BREW_PACKAGES, dry_run=dry_run)
    success("Homebrew phase complete.")


# ---------------------------------------------------------------------------
# Phase 2 — Pip packages
# ---------------------------------------------------------------------------

def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")
    info("Aether-Z uses only Python standard-library modules — no pip packages required.")
    info("KillerBee pip requirements are handled in the Git phase post-install step.")
    success("Pip phase complete (nothing to install at this stage).")


# ---------------------------------------------------------------------------
# Phase 3 — Go tools (none required)
# ---------------------------------------------------------------------------

def phase_go(dry_run: bool) -> None:
    phase_header("PHASE 3 — Go Tools")
    info("Aether-Z does not use any Go tools — skipping.")
    success("Go phase complete (nothing to install).")


# ---------------------------------------------------------------------------
# Phase 4 — Git repositories
# ---------------------------------------------------------------------------

GIT_REPOS = [
    {
        "url":       "https://github.com/riverloopsec/killerbee",
        "dest":      "/opt/killerbee",
        "post":      ["pip3", "install", "--break-system-packages", "-e", "/opt/killerbee"],
        "post_cwd":  None,
        "label":     "KillerBee",
        "notes":     "ZigBee / IEEE 802.15.4 security toolkit (zbstumbler, zbdump, zbdsniff, etc.)",
    },
    {
        "url":       "https://github.com/IoTsec/Z3sec",
        "dest":      "/opt/z3sec",
        "post":      ["pip3", "install", "--break-system-packages", "-r",
                      "/opt/z3sec/requirements.txt"],
        "post_cwd":  None,
        "label":     "Z3sec",
        "notes":     "ZigBee / ZLL security analysis and touchlink attack tool",
    },
]


def clone_or_update(repo: dict, dry_run: bool) -> None:
    url   = repo["url"]
    dest  = repo["dest"]
    label = repo["label"]
    dest_path = Path(dest)

    if dest_path.exists():
        info(f"{label}: directory exists — pulling latest changes...")
        rc = run(["git", "-C", dest, "pull", "--ff-only"], dry_run=dry_run)
        if rc != 0:
            warn(f"{label}: git pull failed — continuing with existing clone.")
    else:
        info(f"{label}: cloning {url} → {dest}")
        rc = run(["git", "clone", "--depth=1", url, dest], check=True, dry_run=dry_run)
        if rc != 0:
            error(f"{label}: clone failed — skipping post-install steps.")
            return

    if repo.get("post"):
        info(f"{label}: running post-install step...")
        run(repo["post"], cwd=repo.get("post_cwd"), dry_run=dry_run)

    if repo.get("notes"):
        info(f"{label}: {repo['notes']}")


def phase_git(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 4 — Git Repositories")
    if os_id == "macos":
        warn("Skipping KillerBee / Z3sec clones on macOS.")
        warn("These tools require Linux with a USB ZigBee dongle (CC2531 etc.).")
        warn("You may clone manually: git clone https://github.com/riverloopsec/killerbee")
        return
    if os_id == "windows":
        warn("Skipping git tool clones on Windows — not supported.")
        return
    for repo in GIT_REPOS:
        clone_or_update(repo, dry_run)
    success("Git phase complete.")


# ---------------------------------------------------------------------------
# Phase 5 — Symlinks
# ---------------------------------------------------------------------------

SYMLINKS = {
    "/usr/local/bin/aether-z": "/Users/pr0t31n/Aether-Z/aether_z.py",
}


def phase_symlinks(dry_run: bool) -> None:
    phase_header("PHASE 5 — Symlinks")
    for link, target in SYMLINKS.items():
        target_path = Path(target)
        link_path   = Path(link)
        if not target_path.exists():
            warn(f"Target not found: {target} — symlink will be created anyway.")
        if link_path.is_symlink() or link_path.exists():
            info(f"Removing existing: {link}")
            if not dry_run:
                try:
                    link_path.unlink()
                except OSError as exc:
                    error(f"Could not remove {link}: {exc}")
                    continue
        info(f"Creating symlink: {link} → {target}")
        if not dry_run:
            try:
                link_path.symlink_to(target)
                if target_path.exists():
                    target_path.chmod(0o755)
                success(f"Symlink created: {link}")
            except OSError as exc:
                error(f"Could not create symlink {link}: {exc}")


# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

VERIFY_TOOLS = [
    # KillerBee suite
    "zbstumbler",
    "zbdump",
    "zbdsniff",
    "zbid",
    "zbscapy",
    "zbreplay",
    "zbassocflood",
    "zbpanidconflictflood",
    "zbfind",
    # Analysis tools
    "tshark",
    "binwalk",
    "openocd",
    # System tools
    "git",
    "python3",
]


def run_check() -> bool:
    """Run a quick syntax check on aether_z.py. Returns True on success."""
    aether_z = Path(__file__).parent / "aether_z.py"
    if not aether_z.exists():
        warn(f"aether_z.py not found at {aether_z}")
        return False
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(aether_z)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        success("aether_z.py syntax check: PASS")
        return True
    else:
        error(f"aether_z.py syntax check: FAIL\n{result.stderr}")
        return False


def print_summary(os_id: str) -> None:
    phase_header("POST-INSTALL SUMMARY")
    all_ok = True
    for tool in VERIFY_TOOLS:
        found = shutil.which(tool)
        if found:
            success(f"{tool:30s} found at {found}")
        else:
            warn(f"{tool:30s} NOT FOUND")
            all_ok = False

    print()
    # Check git repos
    for repo in GIT_REPOS:
        dest = Path(repo["dest"])
        if dest.exists():
            success(f"{repo['label']:30s} cloned at {dest}")
        else:
            warn(f"{repo['label']:30s} NOT cloned at {dest}")
            all_ok = False

    print()
    if all_ok:
        success("All tools and repositories verified successfully.")
    else:
        warn("Some tools were not found. Check output above and install manually if needed.")

    # Syntax check
    run_check()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aether-Z installer — ZigBee penetration testing orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 install.py
  sudo python3 install.py --check
  sudo python3 install.py --skip-git
""",
    )
    p.add_argument("--skip-apt",  action="store_true",
                   help="Skip system package installation")
    p.add_argument("--skip-pip",  action="store_true",
                   help="Skip pip package installation")
    p.add_argument("--skip-go",   action="store_true",
                   help="Skip Go tool installation (no-op for Aether-Z)")
    p.add_argument("--skip-git",  action="store_true",
                   help="Skip git repository cloning")
    p.add_argument("--check",     action="store_true",
                   help="Dry-run — print commands without executing")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 60, GREEN, bold=True)
    cprint("  Aether-Z Installer  —  v1.0.0", GREEN, bold=True)
    cprint("  ZigBee / IEEE 802.15.4 Penetration Test Orchestrator", GREEN, bold=True)
    cprint("=" * 60 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    os_id = detect_os()
    info(f"Detected OS: {os_id}")
    info(f"Python: {sys.version.split()[0]}")

    # Windows gate
    if os_id == "windows":
        error("Aether-Z is designed for Linux. Windows is not supported.")
        error("ZigBee hardware interfaces require Linux with CC2531/HackRF USB support.")
        sys.exit(1)

    # macOS advisory
    if os_id == "macos":
        warn("macOS detected. ZigBee dongle support and KillerBee require Linux.")
        warn("Only Homebrew support libraries will be installed on macOS.")

    # Phase 1 — System packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "suse":
            phase_zypper(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            warn(f"Unknown OS '{os_id}' — skipping system package phase.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — Pip
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — Go
    if not args.skip_go:
        phase_go(dry_run)
    else:
        info("Skipping Go phase (--skip-go).")

    # Phase 4 — Git
    if not args.skip_git:
        phase_git(os_id, dry_run)
    else:
        info("Skipping git phase (--skip-git).")

    # Phase 5 — Symlinks
    if not dry_run and os_id != "windows":
        if is_root():
            phase_symlinks(dry_run)
        else:
            warn("Not running as root — skipping symlink creation.")
    elif dry_run:
        phase_symlinks(dry_run)

    # Summary and verification
    print_summary(os_id)

    print()
    cprint("  Aether-Z installation complete.", GREEN, bold=True)
    cprint("  Run:  aether-z --help  to get started.", CYAN)
    cprint("  Docs: /Users/pr0t31n/Aether-Z/README.md\n", CYAN)


if __name__ == "__main__":
    main()
