#!/usr/bin/env python3
# install.py — Aether-Z ZigBee Penetration Test Orchestrator
# VERSION: 1.1.0 (referenced from /opt/pr0t31n/Aether-Z/VERSION — do not bump here)
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
    "libgcrypt-dev",
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
    "libgcrypt-devel",
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

    try:
        _installed = set(subprocess.run(
            base_cmd + ["list", "--formula", "-1"],
            capture_output=True, text=True, check=True).stdout.strip().splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        _installed = set()
    _missing = [p for p in BREW_PACKAGES if p not in _installed]
    for p in BREW_PACKAGES:
        if p in _installed:
            info(f"✓ {p} already installed")
    if _missing:
        info(f"Installing brew packages: {' '.join(_missing)}")
        run(base_cmd + ["install"] + _missing, dry_run=dry_run)
    else:
        info("All brew packages already installed.")
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
        "label":     "KillerBee",
        "notes":     "ZigBee / IEEE 802.15.4 security toolkit (zbstumbler, zbdump, zbdsniff, etc.)",
    },
    {
        "url":       "https://github.com/IoTsec/Z3sec",
        "dest":      "/opt/z3sec",
        "label":     "Z3sec",
        "notes":     "ZigBee / ZLL security analysis and touchlink attack tool",
    },
    {
        "url":       "https://github.com/travisgoodspeed/goodfet",
        "dest":      "/opt/goodfet",
        "label":     "GoodFET",
        "notes":     "JTAG / SPI / I2C / CC2530 bus adapter toolkit (goodfet.cc for CC chip programming)",
    },
]

_GOODFET_SCRIPTS = [
    "goodfet", "goodfet.arm7", "goodfet.arm9", "goodfet.avr",
    "goodfet.bsl", "goodfet.bslold", "goodfet.bslv2", "goodfet.cc",
    "goodfet.cc2500", "goodfet.ccspi", "goodfet.i2ceeprom",
    "goodfet.jtag", "goodfet.maxusb", "goodfet.monitor", "goodfet.msp430",
    "goodfet.nrf", "goodfet.pic", "goodfet.rf", "goodfet.spi",
    "goodfet.spi25c", "goodfet.spiflash",
]


def _pip_installed(pkg_spec: str) -> bool:
    """Check whether a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "pyusb": "usb", "scapy": "scapy", "pyserial": "serial",
        "python-whois": "whois", "beautifulsoup4": "bs4",
        "pyOpenSSL": "OpenSSL", "dnspython": "dns", "pyyaml": "yaml",
        "Pillow": "PIL", "charset-normalizer": "charset_normalizer",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def clone_or_update(repo: dict, dry_run: bool) -> bool:
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
            return False

    if repo.get("notes"):
        info(f"{label}: {repo['notes']}")
    return True


def _install_killerbee(dry_run: bool) -> None:
    """Pre-install pyusb+scapy then editable-install KillerBee.

    KillerBee's setup.py does `import usb` at build time.  Under pip's
    default build isolation that import fails even when pyusb is installed
    system-wide.  Pre-installing the runtime deps and disabling build
    isolation lets the import succeed.
    """
    pre_deps = {"pyusb>=1.0": "pyusb", "scapy": "scapy"}
    missing_deps = []
    for spec, _ in pre_deps.items():
        if _pip_installed(spec):
            info(f"KillerBee:   ✓ {spec} already installed")
        else:
            missing_deps.append(spec)
    if missing_deps:
        info(f"KillerBee: pre-installing {', '.join(missing_deps)}...")
        run(["pip3", "install", "--break-system-packages"] + missing_deps,
            dry_run=dry_run)
    else:
        info("KillerBee: all pre-deps already present")
    info("KillerBee: installing in editable mode (--no-build-isolation)...")
    run(["pip3", "install", "--break-system-packages", "--no-build-isolation",
         "-e", "/opt/killerbee"], dry_run=dry_run)


def _install_z3sec(dry_run: bool) -> None:
    """Install Z3sec via its setup.py (repo has no requirements.txt)."""
    setup_py = Path("/opt/z3sec/setup.py")
    if setup_py.exists():
        info("Z3sec: installing via setup.py...")
        run(["pip3", "install", "--break-system-packages", "-e", "/opt/z3sec"],
            dry_run=dry_run)
    else:
        deps_sh = Path("/opt/z3sec/install_dependencies.sh")
        if deps_sh.exists():
            info("Z3sec: running install_dependencies.sh...")
            run(["bash", str(deps_sh)], cwd="/opt/z3sec", dry_run=dry_run)
        else:
            warn("Z3sec: no setup.py or install_dependencies.sh found — skipping.")


def _install_goodfet(dry_run: bool) -> None:
    """Symlink GoodFET client scripts into PATH.

    GoodFET predates modern Python packaging (no setup.py/pyproject.toml).
    The usable scripts live in client/ — symlink them to /usr/local/bin/.
    """
    client_dir = Path("/opt/goodfet/client")
    if not client_dir.is_dir():
        warn("GoodFET: client/ directory not found — skipping symlinks.")
        return
    pythonpath_file = Path("/opt/goodfet/client/lib")
    info("GoodFET: symlinking client scripts to /usr/local/bin/...")
    for script_name in _GOODFET_SCRIPTS:
        src = client_dir / script_name
        dst = Path("/usr/local/bin") / script_name
        if not src.exists():
            continue
        if dst.is_symlink() or dst.exists():
            if not dry_run:
                try:
                    dst.unlink()
                except OSError:
                    pass
        if not dry_run:
            try:
                dst.symlink_to(src)
                src.chmod(0o755)
            except OSError as exc:
                error(f"Could not symlink {script_name}: {exc}")
                continue
        success(f"  {script_name} → {src}")


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
    if Path("/opt/killerbee").exists():
        _install_killerbee(dry_run)
    if Path("/opt/z3sec").exists():
        _install_z3sec(dry_run)
    if Path("/opt/goodfet").exists():
        _install_goodfet(dry_run)
    success("Git phase complete.")


# ---------------------------------------------------------------------------
# Phase 5 — Symlinks
# ---------------------------------------------------------------------------

SYMLINKS = {
    "/usr/local/bin/aether-z": "/opt/pr0t31n/Aether-Z/aether_z.py",
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
    # GoodFET
    "goodfet.cc",
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
    cprint("  Aether-Z Installer  —  v1.1.0", GREEN, bold=True)
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
    cprint("  Docs: /opt/pr0t31n/Aether-Z/README.md\n", CYAN)


if __name__ == "__main__":
    main()
