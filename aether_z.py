#!/usr/bin/env python3
"""
Aether-Z — ZigBee / IEEE 802.15.4 Penetration Test Orchestrator
================================================================
Orchestrates multi-phase ZigBee security assessments via:
  Phase 0  — RF Environment Survey           (zbstumbler / zbfind)
  Phase 1  — Network Key Recovery            (zbdsniff / zbdump + z3sec)
  Phase 2  — Active Enumeration              (zbid / zbscapy / tshark)
  Phase 3  — Attack Testing                  (zbreplay / zbassocflood / zbpanidconflictflood)
  Phase 4  — Firmware Analysis               (binwalk / goodfet / openocd)

Protocol tokens (emitted to stdout for Spectre frontend):
  __SPECTRE_LOG__     <message>
  __SPECTRE_ERR__     <message>
  __SPECTRE_STATUS__  <json>
  __SPECTRE_FINDING__ <json>
  __SPECTRE_PROMPT__  <message>

Usage:
    sudo python3 aether_z.py --config config.json --project /path/to/project
    sudo python3 aether_z.py --phase key_recovery --interface /dev/ttyUSB0
    sudo python3 aether_z.py --list-phases
"""
from __future__ import annotations

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

import argparse
import json
import os
import socket
import platform
import re
import shutil
import signal
import subprocess
import sys

# 2026-06-12 cross-cutting #156: route subprocess through pr0t31n_tool_runner
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Protocol token configuration ─────────────────────────────────────────────
MANAGED = os.environ.get("SPECTRE_MANAGED") == "1"

_SP_LOG     = "__SPECTRE_LOG__"
_SP_ERR     = "__SPECTRE_ERR__"
_SP_STATUS  = "__SPECTRE_STATUS__"

# §13b/§14j/§14k: run-dir audit log (scan.log + scan.log.json + errors.log), set
# in main() once the project dir is known. _tok() forwards here so every message
# + phase transition is persisted with a timestamp (the token stream is ephemeral).
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_event_log as _el
except Exception:
    _el = None
_RUNLOG = None

try:
    import pr0t31n_pause as _pp
except ImportError:
    _pp = None
_PAUSE = None

_SP_FINDING = "__SPECTRE_FINDING__"
_SP_PROMPT  = "__SPECTRE_PROMPT__"

_AETHER_Z_DIR = Path(__file__).parent.resolve()


# ── Client directory helpers ──────────────────────────────────────────────────

def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """Build a structured project directory:
      <clients_base>/<slug>/<year>/<tool_name>/<slug>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now(timezone.utc).strftime('%Y'))
    dt_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now(timezone.utc).isoformat(),
                "version":      version,
                "hostname":     socket.gethostname(),
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ── In-process state ──────────────────────────────────────────────────────────
_catalogue: dict[str, dict] = {}
_findings_collected: list[dict] = []

# ── Scope enforcement state ───────────────────────────────────────────────────
_scope_panids: set[str] = set()
_scope_eui64s: set[str] = set()


# ── Protocol token emitters ───────────────────────────────────────────────────

def _tok(token: str, msg: str) -> None:
    print(f"{token} {msg}", flush=True)
    # §13b/§14j: persist to the run-dir audit log with a timestamp.
    if _RUNLOG is not None:
        try:
            if token == _SP_LOG:
                _RUNLOG.info(msg)
            elif token == _SP_ERR:
                _RUNLOG.error(msg)
            elif token == _SP_STATUS:
                d = json.loads(msg)
                step = f" — {d['step']}" if d.get("step") else ""
                _RUNLOG.event(f"phase {d.get('phase','?')}: {d.get('status','?')}{step}")
        except Exception:
            pass


def _log(msg: str) -> None:
    _tok(_SP_LOG, msg)


def _err(msg: str) -> None:
    _tok(_SP_ERR, msg)


def _status(phase: str, status: str, step: str = "") -> None:
    _tok(_SP_STATUS, json.dumps({
        "phase": phase,
        "status": status,
        "step": step,
        "ts": datetime.now(timezone.utc).isoformat(),
    }))


def _finding(finding_id: str, output_file: str = "", data: Optional[dict] = None) -> None:
    entry = _catalogue.get(finding_id, {})
    rec = {
        "id": finding_id,
        "title": entry.get("title", finding_id),
        "severity": entry.get("severity", "HIGH"),
        "cvss_score": entry.get("cvss_score"),
        "cvss_vector": entry.get("cvss_vector", ""),
        "category": entry.get("category", ""),
        "description": entry.get("description", ""),
        "remediation": entry.get("remediation", ""),
        "data": data or {},
        "output_file": output_file,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    _findings_collected.append(rec)
    _tok(_SP_FINDING, json.dumps(rec))


def _prompt(msg: str) -> str:
    _tok(_SP_PROMPT, msg)
    if MANAGED:
        return ""
    try:
        return input(f"[?] {msg} > ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


# ── Findings catalogue ────────────────────────────────────────────────────────

def _load_catalogue() -> None:
    global _catalogue
    cat_path = _AETHER_Z_DIR / "findings_catalogue.json"
    if cat_path.exists():
        try:
            data = json.loads(cat_path.read_text(encoding="utf-8"))
            entries = data.get("findings", data) if isinstance(data, dict) else data
            _catalogue = {e["id"]: e for e in entries if "id" in e}
        except Exception as exc:
            _err(f"Catalogue load error: {exc}")


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config(path: Path) -> dict:
    defaults: dict = {
        "interface": "/dev/ttyUSB0",
        "channel": None,
        "channels": [11, 15, 20, 25],
        "target_panids": [],
        "target_eui64s": [],
        "timeout_per_phase": 300,
        "capture_duration": 3600,
        "phases": {
            "survey": True,
            "key_recovery": True,
            "enumeration": True,
            "attacks": False,
            "firmware": False,
        },
        "tools": {
            "zbstumbler": "zbstumbler",
            "zbdump": "zbdump",
            "zbdsniff": "zbdsniff",
            "zbscapy": "zbscapy",
            "zbreplay": "zbreplay",
            "zbassocflood": "zbassocflood",
            "zbpanidconflictflood": "zbpanidconflictflood",
            "zbfind": "zbfind",
            "zbid": "zbid",
            "z3sec": "python3 /opt/z3sec/z3sec.py",
            "goodfet": "goodfet.cc",
            "openocd": "openocd",
            "binwalk": "binwalk",
            "tshark": "tshark",
        },
        "zll_master_key": "",
        "network_keys": [],
        "known_tclk": "5A6967426565416C6C69616E636530392039",
        "scope": {"panids": [], "eui64s": []},
        "output_dir": "aether_z_output",
        "physical_access": False,
        "injection_authorized": False,
        "dos_authorized": False,
    }

    if not path.exists():
        _err(f"Config not found: {path} — using built-in defaults")
        return defaults

    try:
        user_cfg = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err(f"Config parse error: {exc} — using built-in defaults")
        return defaults

    # Deep-merge user config over defaults
    merged = {**defaults}
    for k, v in user_cfg.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    return merged


# ── Scope helpers ─────────────────────────────────────────────────────────────

def _in_scope_panid(panid: str) -> bool:
    if not _scope_panids:
        return True
    return panid.upper() in _scope_panids


def _in_scope_eui64(eui64: str) -> bool:
    if not _scope_eui64s:
        return True
    return eui64.upper() in _scope_eui64s


# ── Tool check ────────────────────────────────────────────────────────────────

def _check_tool(name: str) -> Optional[str]:
    """Return the full path to 'name' if it exists on PATH, else None."""
    return shutil.which(name)


def _resolve_tool(cfg: dict, key: str) -> Optional[str]:
    """Resolve a tool from config tools dict. Returns first token if found on PATH."""
    tool_str = cfg.get("tools", {}).get(key, key)
    parts = tool_str.split()
    # For compound commands like "python3 /opt/z3sec/z3sec.py", check interpreter
    binary = parts[0]
    if shutil.which(binary):
        return tool_str  # Return full command string
    return None


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, cwd: Optional[str] = None,
         output_file: Optional[str] = None) -> tuple[str, int]:
    """Run a command with timeout; return (stdout+stderr, returncode).
    2026-06-12 cross-cutting #156: when pr0t31n_tool_runner is available
    every invocation auto-emits a `.log` sibling per §14."""
    try:
        if _ur is not None:
            r = _ur.run_tool(
                cmd, timeout=timeout, output_file=output_file,
                cwd=cwd, tool_name=(cmd[0] if cmd else ""),
            )
        else:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
            )
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", -1
    except FileNotFoundError:
        return f"(executable not found: {cmd[0]})", 127
    except Exception as exc:
        return str(exc), -1


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **kwargs)


def _kill_proc(proc: subprocess.Popen, wait_secs: int = 5) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=wait_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    except Exception:
        pass


# ── Findings persistence ──────────────────────────────────────────────────────

def _save_findings(output_dir: Path) -> None:
    out = output_dir / "findings_spectre.json"
    out.write_text(json.dumps(_findings_collected, indent=2), encoding="utf-8")
    _log(f"Findings written: {out} ({len(_findings_collected)} item(s))")


# ── Phase 0: RF Environment Survey ───────────────────────────────────────────

def phase_survey(cfg: dict, project_dir: Path) -> None:
    """
    Phase 0: Passive RF survey of all 802.15.4 channels.
    Uses zbstumbler to enumerate ZigBee PANs, channels, and coordinator
    EUI64s. Falls back to zbfind if zbstumbler is unavailable.
    Discovers network topology without transmitting any frames.
    """
    phase_id = "survey"
    timeout = cfg.get("timeout_per_phase", 300)
    iface = cfg.get("interface", "/dev/ttyUSB0")
    channels = cfg.get("channels", [11, 15, 20, 25])
    tools = cfg.get("tools", {})

    survey_dir = project_dir / "survey"
    survey_dir.mkdir(parents=True, exist_ok=True)

    zbstumbler_bin = _check_tool(tools.get("zbstumbler", "zbstumbler"))
    zbfind_bin = _check_tool(tools.get("zbfind", "zbfind"))

    if not zbstumbler_bin and not zbfind_bin:
        _log("[~] zbstumbler and zbfind not found — skipping survey phase")
        _status(phase_id, "skipped", "zbstumbler and zbfind not installed")
        return

    _status(phase_id, "running", "Starting ZigBee RF environment survey")
    _log("=" * 60)
    _log("AUTHORIZED USE ONLY. Explicit written permission required.")
    _log(f"Aether-Z ZigBee Penetration Test Orchestrator v{VERSION}")
    _log(f"Interface: {iface}")
    _log(f"Channels : {channels}")
    _log("=" * 60)

    discovered_pans: list[dict] = []

    # ── Primary: zbstumbler ────────────────────────────────────────────────
    if zbstumbler_bin:
        for ch in channels:
            out_file = survey_dir / f"zbstumbler_ch{ch}.txt"
            _log(f"[0] zbstumbler: scanning channel {ch} for {timeout}s...")
            _status(phase_id, "running", f"zbstumbler channel {ch}")

            cmd = [zbstumbler_bin, "-i", iface, "-c", str(ch)]
            proc = None
            lines_out: list[str] = []
            try:
                proc = _popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                if proc.stdout is None:
                    raise RuntimeError("zbstumbler stdout unavailable")
                deadline = time.time() + min(timeout // len(channels), 60)
                while time.time() < deadline:
                    try:
                        line = proc.stdout.readline()
                    except Exception:
                        break
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if decoded:
                        _log(decoded)
                        lines_out.append(decoded)
                        # Parse zbstumbler output:
                        # "New PAN! Coordinator: XX:XX:XX:XX:XX:XX:XX:XX PANID: 0xXXXX Channel: XX"
                        m = re.search(
                            r'(?:New PAN|Coordinator)[^\n]*?'
                            r'(?:Coordinator:\s*([\w:]+))?[^\n]*?'
                            r'PANID:\s*(0x[0-9A-Fa-f]+)[^\n]*?'
                            r'Channel:\s*(\d+)',
                            decoded, re.I,
                        )
                        if m:
                            coord = m.group(1) or ""
                            panid = m.group(2).upper()
                            disc_ch = int(m.group(3))
                            if not any(p["panid"] == panid for p in discovered_pans):
                                discovered_pans.append({
                                    "panid": panid,
                                    "coordinator_eui64": coord,
                                    "channel": disc_ch,
                                    "source": "zbstumbler",
                                })
                                _log(f"  [+] PAN discovered: {panid} coord={coord} ch={disc_ch}")
            except Exception as exc:
                _err(f"zbstumbler channel {ch} error: {exc}")
            finally:
                if proc is not None:
                    _kill_proc(proc)
            out_file.write_text("\n".join(lines_out), encoding="utf-8")

    # ── Fallback: zbfind ──────────────────────────────────────────────────
    elif zbfind_bin:
        out_file = survey_dir / "zbfind_output.txt"
        _log(f"[0] zbfind: passive scan on {iface}...")
        _status(phase_id, "running", "zbfind passive scan")
        cmd = [zbfind_bin, "-i", iface]
        out, rc = _run(cmd, timeout=min(timeout, 120))
        _log(out[:4000])
        out_file.write_text(out, encoding="utf-8")
        for line in out.splitlines():
            m = re.search(r'PANID[:\s]+(0x[0-9A-Fa-f]+)', line, re.I)
            if m:
                panid = m.group(1).upper()
                if not any(p["panid"] == panid for p in discovered_pans):
                    discovered_pans.append({
                        "panid": panid,
                        "coordinator_eui64": "",
                        "channel": 0,
                        "source": "zbfind",
                    })

    # ── Persist survey results ────────────────────────────────────────────
    survey_json = survey_dir / "discovered_pans.json"
    survey_json.write_text(json.dumps(discovered_pans, indent=2), encoding="utf-8")
    _log(f"[0] Survey complete — {len(discovered_pans)} PAN(s) discovered")

    # Check for permanently open join windows via zbstumbler beacon flags
    # zbstumbler reports "Join: Open" when the coordinator beacon has permit join set
    join_open_pans: list[dict] = []
    for survey_file in survey_dir.glob("zbstumbler_ch*.txt"):
        content = survey_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            if re.search(r'join[:\s]+open|permit.*join.*true', line, re.I):
                m = re.search(r'PANID[:\s]+(0x[0-9A-Fa-f]+)', line, re.I)
                if m:
                    panid = m.group(1).upper()
                    join_open_pans.append({"panid": panid, "line": line.strip()})

    if join_open_pans:
        for pan in join_open_pans:
            _finding(
                "AETHZ-010",
                output_file=str(survey_json),
                data={"panid": pan["panid"], "beacon_line": pan["line"]},
            )

    _status(phase_id, "complete", f"{len(discovered_pans)} PAN(s) found")


# ── Phase 1: Network Key Recovery ────────────────────────────────────────────

def phase_key_recovery(cfg: dict, project_dir: Path) -> None:
    """
    Phase 1: Passive network key recovery.

    Strategy A — zbdsniff: passive sniffer that detects key transport frames
                 sent during device join using the well-known TCLK.
    Strategy B — zbdump + z3sec: raw packet capture followed by z3sec
                 offline analysis to extract keys from captures.
    Strategy C — Scan gateway config files for plaintext keys
                 (Zigbee2MQTT / Home Assistant ZHA).

    Emits AETHZ-001 when a key is recovered, AETHZ-002 when the default
    TCLK is confirmed, AETHZ-003 when plaintext config keys are found.
    """
    phase_id = "key_recovery"
    timeout = cfg.get("timeout_per_phase", 300)
    iface = cfg.get("interface", "/dev/ttyUSB0")
    channels = cfg.get("channels", [11, 15, 20, 25])
    channel = cfg.get("channel")
    known_tclk = cfg.get("known_tclk", "5A6967426565416C6C69616E636530392039")
    tools = cfg.get("tools", {})

    key_dir = project_dir / "key_recovery"
    key_dir.mkdir(parents=True, exist_ok=True)

    zbdsniff_bin = _check_tool(tools.get("zbdsniff", "zbdsniff"))
    zbdump_bin = _check_tool(tools.get("zbdump", "zbdump"))
    z3sec_cmd = _resolve_tool(cfg, "z3sec")

    if not zbdsniff_bin and not zbdump_bin:
        _log("[~] zbdsniff and zbdump not found — skipping key_recovery phase")
        _status(phase_id, "skipped", "zbdsniff and zbdump not installed")
        return

    _status(phase_id, "running", "Passive key recovery — monitoring join events")

    recovered_keys: list[str] = []
    default_tclk_seen = False

    # ── Strategy A: zbdsniff ──────────────────────────────────────────────
    if zbdsniff_bin:
        scan_channels = [channel] if channel else channels
        for ch in scan_channels:
            out_file = key_dir / f"zbdsniff_ch{ch}.txt"
            _log(f"[1] zbdsniff: listening on channel {ch} for {timeout}s...")
            _status(phase_id, "running", f"zbdsniff channel {ch}")

            cmd = [zbdsniff_bin, "-i", iface, "-c", str(ch)]
            proc = None
            lines_out: list[str] = []
            try:
                proc = _popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                if proc.stdout is None:
                    raise RuntimeError("zbdsniff stdout unavailable")
                per_ch_timeout = min(timeout // len(scan_channels), 120)
                deadline = time.time() + per_ch_timeout
                while time.time() < deadline:
                    try:
                        line = proc.stdout.readline()
                    except Exception:
                        break
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if not decoded:
                        continue
                    _log(decoded)
                    lines_out.append(decoded)

                    # zbdsniff output patterns:
                    # "Found network key: AABBCCDDEEFF..."
                    # "Using default Trust Center Link Key"
                    key_m = re.search(
                        r'(?:network key|nwk key|found key)[:\s]+([0-9A-Fa-f]{32,})',
                        decoded, re.I,
                    )
                    if key_m:
                        key_hex = key_m.group(1).upper()
                        if key_hex not in recovered_keys:
                            recovered_keys.append(key_hex)
                            _log(f"  [+] Network key recovered: {key_hex}")
                            _finding(
                                "AETHZ-001",
                                output_file=str(out_file),
                                data={
                                    "channel": ch,
                                    "network_key": key_hex,
                                    "method": "zbdsniff join intercept",
                                },
                            )

                    if re.search(r'default.*tclk|ZigBeeAlliance09|well.known.*key', decoded, re.I):
                        if not default_tclk_seen:
                            default_tclk_seen = True
                            _finding(
                                "AETHZ-002",
                                output_file=str(out_file),
                                data={"channel": ch, "tclk": known_tclk},
                            )
            except Exception as exc:
                _err(f"zbdsniff channel {ch} error: {exc}")
            finally:
                if proc is not None:
                    _kill_proc(proc)
            out_file.write_text("\n".join(lines_out), encoding="utf-8")

    # ── Strategy B: zbdump + z3sec offline analysis ───────────────────────
    if zbdump_bin:
        scan_channels = [channel] if channel else channels[:2]  # limit capture channels
        for ch in scan_channels:
            cap_file = key_dir / f"zbdump_ch{ch}.pcap"
            _log(f"[1] zbdump: raw capture on channel {ch} for {min(timeout // 2, 90)}s...")
            _status(phase_id, "running", f"zbdump raw capture channel {ch}")

            cap_timeout = min(timeout // 2, 90)
            cmd = [zbdump_bin, "-i", iface, "-c", str(ch), "-w", str(cap_file)]
            proc = None
            try:
                proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(cap_timeout)
            except Exception as exc:
                _err(f"zbdump error: {exc}")
            finally:
                if proc is not None:
                    _kill_proc(proc)

            if cap_file.exists() and cap_file.stat().st_size > 0:
                _log(f"[1] Capture written: {cap_file} ({cap_file.stat().st_size} bytes)")

                # z3sec offline key extraction
                if z3sec_cmd:
                    _log(f"[1] z3sec: analysing {cap_file}...")
                    _status(phase_id, "running", "z3sec key extraction")
                    z3_parts = z3sec_cmd.split()
                    z3_out_file = key_dir / f"z3sec_ch{ch}.txt"
                    z3_cmd = z3_parts + ["--pcap", str(cap_file), "--tclk", known_tclk]
                    z3_out, z3_rc = _run(z3_cmd, timeout=120)
                    _log(z3_out[:4000])
                    z3_out_file.write_text(z3_out, encoding="utf-8")

                    # Parse z3sec output for recovered keys
                    for line in z3_out.splitlines():
                        key_m = re.search(
                            r'(?:network key|nwk key)[:\s]+([0-9A-Fa-f]{32,})',
                            line, re.I,
                        )
                        if key_m:
                            key_hex = key_m.group(1).upper()
                            if key_hex not in recovered_keys:
                                recovered_keys.append(key_hex)
                                _log(f"  [+] z3sec: network key extracted: {key_hex}")
                                _finding(
                                    "AETHZ-001",
                                    output_file=str(cap_file),
                                    data={
                                        "channel": ch,
                                        "network_key": key_hex,
                                        "method": "z3sec offline analysis",
                                    },
                                )

    # ── Strategy C: Gateway config file scan ──────────────────────────────
    _status(phase_id, "running", "Scanning gateway configuration files")
    _log("[1] Scanning for plaintext ZigBee keys in gateway config files...")

    config_search_paths = [
        Path("/opt/zigbee2mqtt/data/configuration.yaml"),
        Path("/opt/zigbee2mqtt/data/configuration.yml"),
        Path(os.path.expanduser("~/.homeassistant/.storage/core.config_entries")),
        Path("/config/.storage/core.config_entries"),
        Path("/data/zigbee2mqtt/configuration.yaml"),
        Path("/usr/share/hassio/homeassistant/.storage/core.config_entries"),
    ]
    # Also glob common locations
    for base in [Path("/opt"), Path("/etc"), Path(os.path.expanduser("~"))]:
        if base.exists():
            for p in base.rglob("configuration.yaml"):
                if "zigbee" in str(p).lower() and p not in config_search_paths:
                    config_search_paths.append(p)
                    if len(config_search_paths) > 20:
                        break

    config_key_pattern = re.compile(
        r'(?:network_key|network-key|nwk_key|encryption_key)["\s:]+([0-9A-Fa-f]{32,})',
        re.I,
    )
    for cfg_path in config_search_paths:
        if not cfg_path.exists():
            continue
        try:
            content = cfg_path.read_text(encoding="utf-8", errors="replace")
            m = config_key_pattern.search(content)
            if m:
                found_key = m.group(1).upper()
                _log(f"  [+] Plaintext network key in {cfg_path}: {found_key[:8]}...")
                _finding(
                    "AETHZ-003",
                    output_file=str(cfg_path),
                    data={"config_file": str(cfg_path), "key_prefix": found_key[:8]},
                )
        except Exception:
            pass

    # ── Save recovered keys ───────────────────────────────────────────────
    keys_json = key_dir / "recovered_keys.json"
    keys_json.write_text(
        json.dumps({"recovered_keys": recovered_keys, "default_tclk_seen": default_tclk_seen}, indent=2),
        encoding="utf-8",
    )
    # 2026-06-11 review round 5: ZigBee 3.0 install-code derivation
    try:
        _zigbee3_install_code_derive(cfg, output_dir, recovered_keys)
    except Exception as exc:
        _err(f"[1c] install-code derive error: {exc}")
    # 2026-06-11 review round 5: Touchlink replay-only (passive)
    try:
        _touchlink_replay_only(cfg, output_dir)
    except Exception as exc:
        _err(f"[1d] touchlink replay-only error: {exc}")

    _log(f"[1] Key recovery complete — {len(recovered_keys)} key(s) recovered")
    _status(phase_id, "complete", f"{len(recovered_keys)} key(s) recovered")


# ── Phase 1c: ZigBee 3.0 install-code derivation ──────────────────────────────
# 2026-06-11 review round 5: ZigBee 3.0 requires every device to ship with
# a printed install-code (8/10/14/18 bytes + 2-byte CRC).  The device
# joins by deriving its initial trust-center link key as
#   TCLK = AES-128-MMO(install_code)  (per ZigBee Pro spec sec B.3)
# When the operator provides install-codes for in-scope devices, we
# pre-derive the expected TCLKs so any sniffed APS commissioning frame
# can be decrypted offline.  zbpython.aes_mmo() is the cryptographic
# primitive when killerbee is installed; otherwise we fall back to a
# pure-Python AES-MMO implementation via cryptography.

def _zigbee3_install_code_derive(cfg: dict, output_dir: Path,
                                   recovered_keys: list) -> None:
    install_codes = cfg.get("install_codes", []) or []
    if not install_codes:
        _log("[1c] ZB3 install-code: none configured — skipping")
        return

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        _log("[1c] ZB3 install-code: cryptography package missing — skipping")
        return

    out_dir = output_dir / "install_codes"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _aes_mmo(data: bytes) -> bytes:
        """Matyas-Meyer-Oseas one-way hash on AES-128 — per ZigBee Pro B.3."""
        h = bytes(16)
        # Append 0x80 + zero-pad + 2-byte length-in-bits (big-endian) per spec
        bit_len = len(data) * 8
        padded = data + b"\x80"
        while (len(padded) % 16) != 14:
            padded += b"\x00"
        padded += bit_len.to_bytes(2, "big")
        backend = default_backend()
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            cipher = Cipher(algorithms.AES(h), modes.ECB(), backend=backend)
            enc = cipher.encryptor().update(block) + cipher.encryptor().finalize()
            h = bytes(a ^ b for a, b in zip(enc, block))
        return h

    derived = []
    for entry in install_codes:
        eui64 = (entry.get("eui64") or "").upper()
        ic_hex = (entry.get("install_code") or "").replace(":", "").replace(" ", "").replace("-", "")
        if not eui64 or not ic_hex:
            continue
        try:
            ic_bytes = bytes.fromhex(ic_hex)
        except ValueError:
            _log(f"[1c] ZB3 install-code: bad hex for {eui64}, skipping")
            continue
        # Valid install-code lengths (with CRC): 8/10/14/18 bytes
        if len(ic_bytes) not in (8, 10, 14, 18):
            _log(f"[1c] ZB3 install-code: {eui64} length {len(ic_bytes)} not 8/10/14/18 — accepting anyway")
        # Strip the 2-byte CRC from the end to feed the actual key material
        key_material = ic_bytes[:-2] if len(ic_bytes) > 2 else ic_bytes
        tclk = _aes_mmo(key_material)
        rec = {
            "eui64": eui64,
            "install_code_hex": ic_hex,
            "derived_tclk_hex": tclk.hex().upper(),
            "method": "AES-MMO of install-code (ZigBee Pro B.3)",
        }
        derived.append(rec)
        recovered_keys.append({
            "eui64": eui64,
            "key": tclk.hex().upper(),
            "type": "trust_center_link_key",
            "source": "install_code_derive",
        })

    if derived:
        manifest = out_dir / "derived_tclks.json"
        manifest.write_text(json.dumps(derived, indent=2), encoding="utf-8")
        _finding(
            "zigbee3_install_code_derive",
            output_file=str(manifest),
            data={"derived_count": len(derived),
                  "method": "AES-MMO install-code → TCLK (ZB3 join)",
                  "attack": "Operator-provided install-codes pre-derive TCLKs for offline APS decryption"},
        )
        _log(f"[1c] ZB3 install-code: {len(derived)} TCLK(s) derived")
    else:
        _log("[1c] ZB3 install-code: no valid install-codes found")


# ── Phase 1d: Touchlink replay-only (passive) ─────────────────────────────────
# 2026-06-11 review round 5: complements the existing active touchlink
# attack (3c) which requires injection_authorized.  This passive variant
# scans any pre-existing pcap files for ZLL commissioning frames and
# emits findings when the master key is in use or when devices are
# discoverable.  No injection occurs — read-only on the pcap files.

def _touchlink_replay_only(cfg: dict, output_dir: Path) -> None:
    pcaps = list(output_dir.glob("**/*.pcap")) + list(output_dir.glob("**/*.pcapng"))
    if not pcaps:
        _log("[1d] Touchlink replay-only: no pcap files to inspect")
        return
    tshark = _check_tool("tshark")
    if not tshark:
        _log("[1d] Touchlink replay-only: tshark not installed — skipping")
        return

    out_dir = output_dir / "touchlink_replay"
    out_dir.mkdir(parents=True, exist_ok=True)

    # ZigBee ZLL commissioning cluster ID = 0x1000
    # ZLL scan request cmd = 0x00, scan response = 0x01, identify = 0x06
    detected = []
    for pcap in pcaps:
        out_file = out_dir / f"{pcap.stem}_zll_scan.txt"
        ts_cmd = [tshark, "-r", str(pcap),
                   "-Y", "zbee_zcl_general.touchlink || zbee_aps.cluster == 0x1000",
                   "-T", "fields",
                   "-e", "frame.number",
                   "-e", "zbee_nwk.src",
                   "-e", "zbee_nwk.dst",
                   "-e", "zbee_zcl_general.touchlink.cmd"]
        out, _ = _run(ts_cmd, timeout=60)
        out_file.write_text(out, encoding="utf-8")
        if out.strip():
            n = len(out.strip().splitlines())
            detected.append({"pcap": str(pcap), "frame_count": n})
            _finding(
                "touchlink_replay_only_detected",
                output_file=str(out_file),
                data={"pcap": str(pcap), "frame_count": n,
                      "method": "passive ZLL commissioning frame detection",
                      "attack": "Touchlink (ZLL) commissioning observed — devices may accept reset/steal"},
            )
            _log(f"[1d] Touchlink replay-only: {n} ZLL frame(s) in {pcap.name}")

    if not detected:
        _log("[1d] Touchlink replay-only: no ZLL commissioning frames detected in any pcap")


# ── Phase 2: Active Enumeration ───────────────────────────────────────────────

def phase_enumeration(cfg: dict, project_dir: Path) -> None:
    """
    Phase 2: Active ZigBee network enumeration.

    Uses zbid and zbscapy to enumerate:
      - Device endpoints and clusters (ZDO)
      - Device EUI64 addresses and short addresses
      - Supported cluster capabilities
      - Network topology (routing table, neighbour table)

    Falls back to tshark for passive pcap-based enumeration.
    Emits AETHZ-011 for unauthenticated ZDO responses.
    """
    phase_id = "enumeration"
    timeout = cfg.get("timeout_per_phase", 300)
    iface = cfg.get("interface", "/dev/ttyUSB0")
    channel = cfg.get("channel")
    channels = cfg.get("channels", [11, 15, 20, 25])
    tools = cfg.get("tools", {})

    enum_dir = project_dir / "enumeration"
    enum_dir.mkdir(parents=True, exist_ok=True)

    zbid_bin = _check_tool(tools.get("zbid", "zbid"))
    zbscapy_bin = _check_tool(tools.get("zbscapy", "zbscapy"))
    tshark_bin = _check_tool(tools.get("tshark", "tshark"))
    zbdump_bin = _check_tool(tools.get("zbdump", "zbdump"))

    if not zbid_bin and not zbscapy_bin and not tshark_bin:
        _log("[~] zbid, zbscapy, and tshark not found — skipping enumeration phase")
        _status(phase_id, "skipped", "zbid / zbscapy / tshark not installed")
        return

    _status(phase_id, "running", "ZigBee network enumeration — ZDO queries")

    target_panids = cfg.get("target_panids", [])
    scan_channels = [channel] if channel else channels
    devices_found: list[dict] = []

    # ── zbid: ZigBee device identification ───────────────────────────────
    if zbid_bin:
        for ch in scan_channels:
            out_file = enum_dir / f"zbid_ch{ch}.txt"
            _log(f"[2] zbid: device identification on channel {ch}...")
            _status(phase_id, "running", f"zbid channel {ch}")

            cmd = [zbid_bin, "-i", iface, "-c", str(ch)]
            out, rc = _run(cmd, timeout=min(timeout // len(scan_channels), 90))
            _log(out[:4000])
            out_file.write_text(out, encoding="utf-8")

            # Parse zbid output for device entries
            # "EUI64: XX:XX:XX:XX:XX:XX:XX:XX  NWK: 0xXXXX  PANID: 0xXXXX"
            for line in out.splitlines():
                eui_m = re.search(
                    r'EUI64[:\s]+((?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2})',
                    line, re.I,
                )
                nwk_m = re.search(r'NWK[:\s]+(0x[0-9A-Fa-f]{4})', line, re.I)
                pan_m = re.search(r'PANID[:\s]+(0x[0-9A-Fa-f]{4})', line, re.I)
                if eui_m:
                    dev = {
                        "eui64": eui_m.group(1).upper(),
                        "nwk_addr": nwk_m.group(1).upper() if nwk_m else "",
                        "panid": pan_m.group(1).upper() if pan_m else "",
                        "channel": ch,
                    }
                    if not any(d["eui64"] == dev["eui64"] for d in devices_found):
                        devices_found.append(dev)
                        _log(f"  [+] Device: {dev['eui64']} nwk={dev['nwk_addr']} pan={dev['panid']}")

                # Detect unauthenticated ZDO responses
                if re.search(r'ZDO.*response|Simple Descriptor|Active Endpoint', line, re.I):
                    _finding(
                        "AETHZ-011",
                        output_file=str(out_file),
                        data={"channel": ch, "zdo_line": line.strip()},
                    )

    # ── zbscapy: cluster-level enumeration ────────────────────────────────
    if zbscapy_bin:
        for ch in scan_channels[:2]:  # limit to first 2 channels
            out_file = enum_dir / f"zbscapy_ch{ch}.txt"
            _log(f"[2] zbscapy: cluster enumeration on channel {ch}...")
            _status(phase_id, "running", f"zbscapy channel {ch}")

            cmd = [zbscapy_bin, "-i", iface, "-c", str(ch), "--enumerate"]
            out, rc = _run(cmd, timeout=min(timeout // 2, 120))
            _log(out[:4000])
            out_file.write_text(out, encoding="utf-8")

            # Look for security-sensitive cluster IDs
            # Cluster 0x0101 = Door Lock, 0x0500 = IAS Zone, 0x0201 = Thermostat
            security_clusters = {
                "0x0101": "Door Lock",
                "0x0500": "IAS Zone",
                "0x0501": "IAS ACE",
                "0x0201": "Thermostat",
                "0x0300": "Color Control",
            }
            for cluster_id, cluster_name in security_clusters.items():
                if cluster_id.lower() in out.lower():
                    _log(f"  [*] Security-sensitive cluster found: {cluster_name} ({cluster_id})")

    # ── tshark passive: decode any captures already in project dir ────────
    if tshark_bin:
        for cap_file in (project_dir / "key_recovery").glob("*.pcap"):
            if not cap_file.exists():
                continue
            out_file = enum_dir / f"tshark_{cap_file.stem}.txt"
            _log(f"[2] tshark: decoding {cap_file.name}...")
            _status(phase_id, "running", f"tshark decode {cap_file.name}")

            # Add any known network keys for decryption
            tshark_cmd = [
                tshark_bin,
                "-r", str(cap_file),
                "-Y", "zbee_nwk or zbee_aps or zbee_zcl or zbee_zdp",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "zbee_nwk.src",
                "-e", "zbee_nwk.dst",
                "-e", "zbee_nwk.src_panid",
                "-e", "zbee_zcl.cluster_id",
                "-e", "zbee_zdp.endpoint",
            ]
            network_keys = cfg.get("network_keys", [])
            for nk in network_keys:
                tshark_cmd += ["-o", f"zbee.nwk.enc_key:{nk}"]

            out, rc = _run(tshark_cmd, timeout=120)
            out_file.write_text(out, encoding="utf-8")
            _log(f"  tshark decode rc={rc}, {len(out.splitlines())} lines")

    # ── Persist enumeration results ───────────────────────────────────────
    enum_json = enum_dir / "devices_found.json"
    enum_json.write_text(json.dumps(devices_found, indent=2), encoding="utf-8")
    _log(f"[2] Enumeration complete — {len(devices_found)} device(s) identified")
    _status(phase_id, "complete", f"{len(devices_found)} device(s) identified")


# ── Phase 3: Attack Testing ───────────────────────────────────────────────────

def phase_attacks(cfg: dict, project_dir: Path) -> None:
    """
    Phase 3: Active attack testing (requires explicit authorisation flags in config).

    Sub-tests (each gated by a separate authorisation check):
      3a — ZCL command replay (AETHZ-004)         requires injection_authorized
      3b — ZCL command injection (AETHZ-005)       requires injection_authorized + network_keys
      3c — ZLL touchlink steal/reset (AETHZ-006/7) requires injection_authorized + zll_master_key
      3d — Association / PAN-ID flood (AETHZ-008)  requires dos_authorized

    All attack sub-tests are skipped unless explicitly authorised.
    """
    phase_id = "attacks"
    timeout = cfg.get("timeout_per_phase", 300)
    iface = cfg.get("interface", "/dev/ttyUSB0")
    channel = cfg.get("channel")
    channels = cfg.get("channels", [11, 15, 20, 25])
    tools = cfg.get("tools", {})
    injection_ok = cfg.get("injection_authorized", False)
    dos_ok = cfg.get("dos_authorized", False)
    network_keys = cfg.get("network_keys", [])
    zll_key = cfg.get("zll_master_key", "")

    attacks_dir = project_dir / "attacks"
    attacks_dir.mkdir(parents=True, exist_ok=True)

    zbreplay_bin = _check_tool(tools.get("zbreplay", "zbreplay"))
    zbscapy_bin = _check_tool(tools.get("zbscapy", "zbscapy"))
    zbassoc_bin = _check_tool(tools.get("zbassocflood", "zbassocflood"))
    zbpanid_bin = _check_tool(tools.get("zbpanidconflictflood", "zbpanidconflictflood"))

    if not any([zbreplay_bin, zbscapy_bin, zbassoc_bin, zbpanid_bin]):
        _log("[~] No attack tools found — skipping attacks phase")
        _status(phase_id, "skipped", "attack tools not installed")
        return

    _status(phase_id, "running", "Attack phase initiated")
    scan_channels = [channel] if channel else channels

    # ── 3a: ZCL Replay Attack ────────────────────────────────────────────
    if not injection_ok:
        _log("[3a] ZCL replay: injection_authorized=false — skipping")
        _status("attacks_replay", "skipped", "injection not authorised in config")
    elif not zbreplay_bin:
        _log("[3a] ZCL replay: zbreplay not found — skipping")
        _status("attacks_replay", "skipped", "zbreplay not installed")
    else:
        _status("attacks_replay", "running", "ZCL replay attack")
        # Collect existing captures to replay
        replay_targets = list((project_dir / "key_recovery").glob("*.pcap"))
        if not replay_targets:
            _log("[3a] No capture files available for replay — skipping")
            _status("attacks_replay", "skipped", "no pcap files available")
        else:
            for cap in replay_targets[:2]:
                out_file = attacks_dir / f"zbreplay_{cap.stem}.txt"
                _log(f"[3a] zbreplay: replaying {cap.name} on {iface}...")
                cmd = [zbreplay_bin, "-i", iface, "-r", str(cap)]
                out, rc = _run(cmd, timeout=min(timeout, 60))
                out_file.write_text(out, encoding="utf-8")
                _log(out[:2000])
                if rc == 0 or re.search(r'success|sent|transmitted', out, re.I):
                    _finding(
                        "AETHZ-004",
                        output_file=str(out_file),
                        data={"pcap": str(cap), "interface": iface, "rc": rc},
                    )
        _status("attacks_replay", "complete")

    # ── 3b: ZCL Command Injection ────────────────────────────────────────
    if not injection_ok:
        _log("[3b] ZCL injection: injection_authorized=false — skipping")
        _status("attacks_inject", "skipped", "injection not authorised in config")
    elif not network_keys:
        _log("[3b] ZCL injection: no network_keys in config — skipping")
        _status("attacks_inject", "skipped", "no network keys available")
    elif not zbscapy_bin:
        _log("[3b] ZCL injection: zbscapy not found — skipping")
        _status("attacks_inject", "skipped", "zbscapy not installed")
    else:
        _status("attacks_inject", "running", "ZCL command injection")
        for ch in scan_channels[:1]:
            out_file = attacks_dir / f"inject_ch{ch}.txt"
            _log(f"[3b] ZCL injection on channel {ch} with recovered key...")
            # zbscapy inject: craft and send authenticated ZCL frame using known nwk key
            cmd = [
                zbscapy_bin, "-i", iface, "-c", str(ch),
                "--inject",
                "--nwk-key", network_keys[0],
                "--cluster", "0x0006",   # On/Off cluster — safe test target
                "--cmd", "0x00",          # Off command
            ]
            out, rc = _run(cmd, timeout=min(timeout, 90))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:2000])
            if rc == 0 or re.search(r'success|accepted|ack', out, re.I):
                _finding(
                    "AETHZ-005",
                    output_file=str(out_file),
                    data={
                        "channel": ch,
                        "cluster": "0x0006 (On/Off)",
                        "command": "0x00 (Off)",
                        "key_used": network_keys[0][:8] + "...",
                    },
                )
        _status("attacks_inject", "complete")

    # ── 3c: ZLL Touchlink ────────────────────────────────────────────────
    if not injection_ok:
        _log("[3c] ZLL touchlink: injection_authorized=false — skipping")
        _status("attacks_touchlink", "skipped", "injection not authorised in config")
    elif not zll_key:
        _log("[3c] ZLL touchlink: zll_master_key not configured — skipping")
        _status("attacks_touchlink", "skipped", "ZLL master key not configured")
    elif not zbscapy_bin:
        _log("[3c] ZLL touchlink: zbscapy not found — skipping")
        _status("attacks_touchlink", "skipped", "zbscapy not installed")
    else:
        _status("attacks_touchlink", "running", "ZLL touchlink scan and steal attempt")
        out_file = attacks_dir / "zll_touchlink.txt"
        _log("[3c] ZLL touchlink: scanning for ZLL devices...")
        # zbscapy touchlink scan — identify ZLL-capable devices
        cmd = [
            zbscapy_bin, "-i", iface,
            "--touchlink-scan",
            "--zll-master-key", zll_key,
        ]
        out, rc = _run(cmd, timeout=min(timeout, 120))
        out_file.write_text(out, encoding="utf-8")
        _log(out[:2000])

        if re.search(r'ZLL device|touchlink.*found|scan.*response', out, re.I):
            _finding(
                "AETHZ-006",
                output_file=str(out_file),
                data={"zll_key_used": zll_key[:8] + "...", "rc": rc},
            )

        # Also check for factory reset acceptance
        if re.search(r'factory reset|reset.*accepted|device.*reset', out, re.I):
            _finding(
                "AETHZ-007",
                output_file=str(out_file),
                data={"method": "touchlink factory reset command"},
            )

        # If ZLL master key detected in use by network, emit AETHZ-015
        if zll_key and re.search(r'ZLL.*network|touchlink.*commissioning|ZLL.*coordinator', out, re.I):
            _finding(
                "AETHZ-015",
                output_file=str(out_file),
                data={"zll_master_key_confirmed": True},
            )

        _status("attacks_touchlink", "complete")

    # ── 3d: Denial of Service ────────────────────────────────────────────
    if not dos_ok:
        _log("[3d] DoS: dos_authorized=false — skipping")
        _status("attacks_dos", "skipped", "DoS not authorised in config")
    else:
        _status("attacks_dos", "running", "ZigBee denial-of-service testing")
        dos_success = False

        # PAN-ID conflict flood
        if zbpanid_bin:
            for ch in scan_channels[:1]:
                out_file = attacks_dir / f"panid_flood_ch{ch}.txt"
                _log(f"[3d] PAN-ID conflict flood on channel {ch}...")
                cmd = [zbpanid_bin, "-i", iface, "-c", str(ch)]
                out, rc = _run(cmd, timeout=min(timeout // 4, 60))
                out_file.write_text(out, encoding="utf-8")
                _log(out[:2000])
                if rc == 0 or re.search(r'flood.*sent|conflict.*sent', out, re.I):
                    dos_success = True

        # Association flood
        if zbassoc_bin:
            for ch in scan_channels[:1]:
                out_file = attacks_dir / f"assoc_flood_ch{ch}.txt"
                _log(f"[3d] Association flood on channel {ch}...")
                cmd = [zbassoc_bin, "-i", iface, "-c", str(ch)]
                out, rc = _run(cmd, timeout=min(timeout // 4, 60))
                out_file.write_text(out, encoding="utf-8")
                _log(out[:2000])
                if rc == 0 or re.search(r'flood.*sent|assoc.*sent', out, re.I):
                    dos_success = True

        if dos_success:
            _finding(
                "AETHZ-008",
                output_file=str(attacks_dir),
                data={
                    "methods": ["panid_conflict_flood", "association_flood"],
                    "channels_tested": scan_channels[:1],
                },
            )
        _status("attacks_dos", "complete")

    # ── 3e: Protocol Fuzzing ─────────────────────────────────────────────
    if not injection_ok:
        _log("[3e] Fuzzing: injection_authorized=false — skipping")
        _status("attacks_fuzz", "skipped", "injection not authorised in config")
    elif not zbscapy_bin:
        _log("[3e] Fuzzing: zbscapy not found — skipping")
        _status("attacks_fuzz", "skipped", "zbscapy not installed")
    else:
        _status("attacks_fuzz", "running", "ZigBee protocol fuzzing")
        for ch in scan_channels[:1]:
            out_file = attacks_dir / f"fuzz_ch{ch}.txt"
            _log(f"[3e] zbscapy: ZigBee protocol fuzzer on channel {ch}...")
            # zbscapy fuzz — send malformed NWK and ZCL frames to discover crashes
            cmd = [
                zbscapy_bin, "-i", iface, "-c", str(ch),
                "--fuzz",
                "--fuzz-layers", "nwk,aps,zcl",
                "--fuzz-count", "50",
            ]
            out, rc = _run(cmd, timeout=min(timeout // 2, 120))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:2000])

            # Detect device crash indicators in zbscapy output
            crash_indicators = re.search(
                r'device.*crash|no.*response|timeout.*after.*fuzz|'
                r'device.*unresponsive|target.*stopped|connection.*lost',
                out, re.I,
            )
            if crash_indicators or (rc == 0 and re.search(r'crash|fault|reset', out, re.I)):
                _finding(
                    "AETHZ-014",
                    output_file=str(out_file),
                    data={
                        "channel": ch,
                        "fuzz_layers": ["nwk", "aps", "zcl"],
                        "frames_sent": 50,
                        "crash_indicator": crash_indicators.group(0) if crash_indicators else "heuristic",
                    },
                )
        _status("attacks_fuzz", "complete")

    _status(phase_id, "complete", "Attack phase complete")


# ── Phase 4: Firmware Analysis ────────────────────────────────────────────────

def phase_firmware(cfg: dict, project_dir: Path) -> None:
    """
    Phase 4: ZigBee device firmware analysis.

    Requires physical access (gated by physical_access flag in config).

    Sub-tests:
      4a — goodfet.cc: dump CC2530/CC2531 flash via JTAG (AETHZ-009)
      4b — openocd: generic ARM/AVR JTAG dump
      4c — binwalk: static analysis of firmware binary for embedded keys
           (AETHZ-009, AETHZ-012, AETHZ-013)

    Points to existing firmware files in project_dir/firmware/ if hardware
    extraction is not being performed in this run.
    """
    phase_id = "firmware"
    timeout = cfg.get("timeout_per_phase", 300)
    tools = cfg.get("tools", {})
    physical_access = cfg.get("physical_access", False)

    firmware_dir = project_dir / "firmware"
    firmware_dir.mkdir(parents=True, exist_ok=True)

    goodfet_bin = _check_tool(tools.get("goodfet", "goodfet.cc"))
    openocd_bin = _check_tool(tools.get("openocd", "openocd"))
    binwalk_bin = _check_tool(tools.get("binwalk", "binwalk"))

    if not goodfet_bin and not openocd_bin and not binwalk_bin:
        _log("[~] goodfet, openocd, and binwalk not found — skipping firmware phase")
        _status(phase_id, "skipped", "firmware analysis tools not installed")
        return

    _status(phase_id, "running", "Firmware analysis phase")

    # ── 4a: goodfet.cc — CC2530/CC2531 flash dump ─────────────────────
    if not physical_access:
        _log("[4a] goodfet: physical_access=false — skipping hardware extraction")
        _status("firmware_goodfet", "skipped", "physical access not authorised")
    elif not goodfet_bin:
        _log("[4a] goodfet.cc not found — skipping CC253x flash dump")
        _status("firmware_goodfet", "skipped", "goodfet not installed")
    else:
        _status("firmware_goodfet", "running", "goodfet CC253x flash dump")
        dump_file = firmware_dir / "cc253x_flash.bin"
        _log(f"[4a] goodfet.cc: dumping CC253x flash to {dump_file}...")
        cmd = [goodfet_bin, "cc", "flash", "dump", str(dump_file)]
        out, rc = _run(cmd, timeout=min(timeout, 300))
        out_log = firmware_dir / "goodfet_output.txt"
        out_log.write_text(out, encoding="utf-8")
        _log(out[:2000])

        if dump_file.exists() and dump_file.stat().st_size > 0:
            _log(f"  [+] Flash dump: {dump_file} ({dump_file.stat().st_size} bytes)")
            _finding(
                "AETHZ-009",
                output_file=str(dump_file),
                data={"method": "goodfet CC253x JTAG", "dump_size": dump_file.stat().st_size},
            )

        if re.search(r'error|fail|could not', out, re.I) and rc != 0:
            _err(f"[4a] goodfet dump failed (rc={rc}) — debug port may be locked")
        _status("firmware_goodfet", "complete" if rc == 0 else "error", f"rc={rc}")

    # ── 4b: openocd — generic JTAG dump ──────────────────────────────
    if not physical_access:
        _log("[4b] openocd: physical_access=false — skipping")
        _status("firmware_openocd", "skipped", "physical access not authorised")
    elif not openocd_bin:
        _log("[4b] openocd not found — skipping generic JTAG dump")
        _status("firmware_openocd", "skipped", "openocd not installed")
    else:
        _status("firmware_openocd", "running", "openocd generic JTAG flash read")
        dump_file = firmware_dir / "openocd_flash.bin"
        out_log = firmware_dir / "openocd_output.txt"
        _log(f"[4b] openocd: reading flash to {dump_file}...")
        # Generic openocd invocation for ARM Cortex-M ZigBee devices
        cmd = [
            openocd_bin,
            "-f", "interface/jlink.cfg",
            "-f", "target/efm32.cfg",
            "-c", f"init; halt; flash read_bank 0 {dump_file} 0 0x100000; shutdown",
        ]
        out, rc = _run(cmd, timeout=min(timeout, 300))
        out_log.write_text(out, encoding="utf-8")
        _log(out[:2000])

        if dump_file.exists() and dump_file.stat().st_size > 0:
            _log(f"  [+] openocd flash dump: {dump_file}")
            _finding(
                "AETHZ-009",
                output_file=str(dump_file),
                data={"method": "openocd JTAG", "dump_size": dump_file.stat().st_size},
            )
        _status("firmware_openocd", "complete" if rc == 0 else "error", f"rc={rc}")

    # ── 4c: binwalk — static analysis ────────────────────────────────
    if not binwalk_bin:
        _log("[4c] binwalk not found — skipping static firmware analysis")
        _status("firmware_binwalk", "skipped", "binwalk not installed")
    else:
        _status("firmware_binwalk", "running", "binwalk static firmware analysis")
        # Collect firmware files: newly dumped + any pre-existing .bin/.hex/.elf
        firmware_targets: list[Path] = list(firmware_dir.glob("*.bin"))
        firmware_targets += list(firmware_dir.glob("*.hex"))
        firmware_targets += list(firmware_dir.glob("*.elf"))
        firmware_targets += list(firmware_dir.glob("*.fw"))

        if not firmware_targets:
            _log("[4c] No firmware files found — place .bin/.hex/.elf in firmware/ dir")
            _status("firmware_binwalk", "skipped", "no firmware files to analyse")
        else:
            for fw_file in firmware_targets[:5]:  # limit to 5 files
                bw_out_file = firmware_dir / f"binwalk_{fw_file.stem}.txt"
                bw_extract_dir = firmware_dir / f"binwalk_extract_{fw_file.stem}"
                _log(f"[4c] binwalk: analysing {fw_file.name}...")

                # Entropy + signature scan
                cmd_sig = [binwalk_bin, "--signature", "--entropy", str(fw_file)]
                out_sig, _ = _run(cmd_sig, timeout=120)
                bw_out_file.write_text(out_sig, encoding="utf-8")
                _log(out_sig[:3000])

                # Extract embedded filesystems
                cmd_ext = [
                    binwalk_bin, "--extract", "--directory", str(bw_extract_dir),
                    "--quiet", str(fw_file),
                ]
                _run(cmd_ext, timeout=180)

                # Search for hardcoded key material in extracted content
                key_pattern = re.compile(r'[0-9A-Fa-f]{32}', re.I)
                zigbee_key_pattern = re.compile(
                    r'(?:zigbee|zb|nwk|network).*?key|'
                    r'ZigBeeAlliance09|5A6967426565416C|'
                    r'(?:0x)?[0-9A-Fa-f]{32}',
                    re.I,
                )

                hardcoded_key_found = False
                for search_path in [fw_file, bw_extract_dir]:
                    if not Path(search_path).exists():
                        continue
                    targets = [Path(search_path)] if Path(search_path).is_file() else \
                        list(Path(search_path).rglob("*"))
                    for t in targets[:50]:
                        if not t.is_file():
                            continue
                        try:
                            content = t.read_bytes()
                            # Check for ZigBeeAlliance09 TCLK bytes in binary
                            tclk_bytes = bytes.fromhex("5A6967426565416C6C69616E636530392039")
                            if tclk_bytes in content:
                                _log(f"  [+] Default TCLK found in {t}")
                                hardcoded_key_found = True
                            # Check for 16-byte runs that look like AES keys
                            text_content = content.decode("latin-1", errors="replace")
                            for m in zigbee_key_pattern.finditer(text_content):
                                if len(m.group(0)) >= 16:
                                    _log(f"  [*] Potential key material at {t}: {m.group(0)[:32]}")
                                    hardcoded_key_found = True
                        except Exception:
                            pass

                if hardcoded_key_found:
                    _finding(
                        "AETHZ-012",
                        output_file=str(fw_file),
                        data={"firmware_file": str(fw_file), "method": "binwalk + pattern scan"},
                    )

                # Check for unsigned OTA upgrade cluster support
                if re.search(r'OTA.*upgrade|0x0019|upgrade.*server', out_sig, re.I):
                    _log(f"  [*] OTA Upgrade cluster reference found in {fw_file.name}")
                    # Need to verify if signature validation is present
                    ota_sig_check = re.search(
                        r'ECDSA|RSA|signature.*verif|verif.*signature|public.*key', out_sig, re.I
                    )
                    if not ota_sig_check:
                        _finding(
                            "AETHZ-013",
                            output_file=str(fw_file),
                            data={
                                "firmware_file": str(fw_file),
                                "ota_cluster": "0x0019",
                                "signature_verification": "not detected",
                            },
                        )

        _status("firmware_binwalk", "complete")

    _log("[4] Firmware analysis phase complete")
    _status(phase_id, "complete", "Firmware analysis complete")


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run(cfg: dict, project_dir: Path) -> None:
    global _scope_panids, _scope_eui64s

    output_dir = project_dir / cfg.get("output_dir", "aether_z_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Scope enforcement
    scope_cfg = cfg.get("scope", {})
    _scope_panids = {p.upper() for p in scope_cfg.get("panids", [])}
    _scope_eui64s = {e.upper() for e in scope_cfg.get("eui64s", [])}
    if _scope_panids or _scope_eui64s:
        _log(f"Scope: {len(_scope_panids)} PAN-ID(s), {len(_scope_eui64s)} EUI64(s) in whitelist")

    phases_cfg = cfg.get("phases", {})
    iface = cfg.get("interface", "/dev/ttyUSB0")

    _log("=" * 60)
    _log("AUTHORIZED USE ONLY. Explicit written permission from the")
    _log("device/network owner is required before any ZigBee assessment.")
    _log("=" * 60)
    _log(f"Aether-Z ZigBee Penetration Test Orchestrator v{VERSION}")
    _log(f"Project  : {project_dir}")
    _log(f"Interface: {iface}")
    _log(f"Channels : {cfg.get('channels', [11, 15, 20, 25])}")
    _log(f"Output   : {output_dir}")
    _log("=" * 60)

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # Phase 0 — Survey
    if phases_cfg.get("survey", True):
        phase_survey(cfg, output_dir)
    else:
        _log("[~] Phase survey disabled in config — skipping")

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # Phase 1 — Key Recovery
    if phases_cfg.get("key_recovery", True):
        phase_key_recovery(cfg, output_dir)
    else:
        _log("[~] Phase key_recovery disabled in config — skipping")

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # Phase 2 — Enumeration
    if phases_cfg.get("enumeration", True):
        phase_enumeration(cfg, output_dir)
    else:
        _log("[~] Phase enumeration disabled in config — skipping")

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # Phase 3 — Attacks
    if phases_cfg.get("attacks", False):
        phase_attacks(cfg, output_dir)
    else:
        _log("[~] Phase attacks disabled in config — skipping (set attacks: true to enable)")

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # Phase 4 — Firmware
    if phases_cfg.get("firmware", False):
        phase_firmware(cfg, output_dir)
    else:
        _log("[~] Phase firmware disabled in config — skipping (set firmware: true to enable)")

    # Persist findings and metadata
    _save_findings(output_dir)

    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "all_phases_done")

    meta = {
        "version": VERSION,
        "project": str(project_dir),
        "interface": iface,
        "channels": cfg.get("channels", [11, 15, 20, 25]),
        "target_panids": cfg.get("target_panids", []),
        "target_eui64s": cfg.get("target_eui64s", []),
        "scope": scope_cfg,
        "phases_run": phases_cfg,
        "output_dir": str(output_dir),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings_count": len(_findings_collected),
        "injection_authorized": cfg.get("injection_authorized", False),
        "dos_authorized": cfg.get("dos_authorized", False),
        "physical_access": cfg.get("physical_access", False),
    }
    (output_dir / "assessment_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    _log(f"Assessment complete — {len(_findings_collected)} finding(s) — output: {output_dir}")
    _status("complete", "complete", str(output_dir))


# ── CLI ───────────────────────────────────────────────────────────────────────

def _startup_tool_check() -> None:
    """Warn about missing KillerBee tools at startup."""
    important = [
        "zbstumbler", "zbdump", "zbdsniff", "zbid", "zbscapy",
        "zbreplay", "zbassocflood", "zbfind",
    ]
    optional = ["binwalk", "tshark", "openocd"]
    missing_important = [t for t in important if not shutil.which(t)]
    missing_optional = [t for t in optional if not shutil.which(t)]
    if missing_important or missing_optional:
        print("[!] Aether-Z startup tool check:", file=sys.stderr)
    for t in missing_important:
        print(f"    MISSING (important): {t}  — run: sudo python3 install.py", file=sys.stderr)
    for t in missing_optional:
        print(f"    MISSING (optional) : {t}  — install manually if needed", file=sys.stderr)
    if missing_important:
        print("[!] Core KillerBee tools missing — most phases will be skipped.\n", file=sys.stderr)


def _parse_args() -> argparse.Namespace:
    _default_cfg = str(_AETHER_Z_DIR / "config.json")
    _default_project = ""

    parser = argparse.ArgumentParser(
        prog="aether-z",
        description="Aether-Z — ZigBee / IEEE 802.15.4 Penetration Test Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 aether_z.py --config config.json --project my_assessment
  sudo python3 aether_z.py --phase key_recovery --interface /dev/ttyUSB0
  sudo python3 aether_z.py --phase firmware --physical-access
  sudo python3 aether_z.py --list-phases
""",
    )
    parser.add_argument("--config", "-c", default=_default_cfg,
                        help="JSON config file (default: next to aether_z.py)")
    parser.add_argument("--project", "-p", default=_default_project,
                        help="Project root directory for all output files")
    parser.add_argument("--interface", "-i",
                        help="ZigBee interface device (e.g. /dev/ttyUSB0)")
    parser.add_argument("--channel", "-C", type=int,
                        help="Lock all phases to this 802.15.4 channel (11-26)")
    parser.add_argument("--channels", nargs="+", type=int, metavar="CH",
                        help="Channels to scan (e.g. --channels 11 15 20 25)")
    parser.add_argument("--phase",
                        choices=["survey", "key_recovery", "enumeration",
                                 "attacks", "firmware"],
                        help="Run a single phase only")
    parser.add_argument("--panid", action="append", dest="panids", metavar="PANID",
                        help="Target PAN-ID (hex, e.g. 0x1A2B); repeatable")
    parser.add_argument("--eui64", action="append", dest="eui64s", metavar="EUI64",
                        help="Target device EUI-64; repeatable")
    parser.add_argument("--network-key", action="append", dest="network_keys",
                        metavar="KEY_HEX",
                        help="Known network key (hex, 32 chars); repeatable")
    parser.add_argument("--timeout", "-t", type=int,
                        help="Per-phase timeout in seconds")
    parser.add_argument("--physical-access", action="store_true",
                        help="Confirm physical access to devices (enables firmware extraction)")
    parser.add_argument("--injection-authorized", action="store_true",
                        help="Confirm injection is authorised (enables attack phases)")
    parser.add_argument("--dos-authorized", action="store_true",
                        help="Confirm DoS testing is authorised")
    parser.add_argument("--scope-panid", action="append", dest="scope_panids",
                        metavar="PANID",
                        help="Scope whitelist PAN-ID (repeatable)")
    parser.add_argument("--scope-eui64", action="append", dest="scope_eui64s",
                        metavar="EUI64",
                        help="Scope whitelist EUI64 (repeatable)")
    parser.add_argument("--list-phases", action="store_true",
                        help="List available phases and exit")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.list_phases:
        print("Aether-Z — Available phases:")
        print("  survey       — Phase 0: RF environment survey               (zbstumbler / zbfind)")
        print("  key_recovery — Phase 1: Network key recovery                (zbdsniff / zbdump / z3sec)")
        print("  enumeration  — Phase 2: Active ZigBee enumeration           (zbid / zbscapy / tshark)")
        print("  attacks      — Phase 3: Attack testing (requires auth)      (zbreplay / zbscapy / zbassocflood)")
        print("  firmware     — Phase 4: Firmware extraction and analysis    (goodfet / openocd / binwalk)")
        sys.exit(0)

    _load_catalogue()
    _startup_tool_check()

    config_path = Path(args.config)
    cfg = _load_config(config_path)

    # CLI overrides
    if args.interface:
        cfg["interface"] = args.interface
    if args.channel is not None:
        cfg["channel"] = args.channel
    if args.channels:
        cfg["channels"] = args.channels
    if args.panids:
        cfg["target_panids"] = args.panids
    if args.eui64s:
        cfg["target_eui64s"] = args.eui64s
    if args.network_keys:
        cfg["network_keys"] = args.network_keys
    if args.timeout is not None:
        cfg["timeout_per_phase"] = args.timeout
    if args.physical_access:
        cfg["physical_access"] = True
    if args.injection_authorized:
        cfg["injection_authorized"] = True
    if args.dos_authorized:
        cfg["dos_authorized"] = True
    if args.scope_panids:
        cfg.setdefault("scope", {})["panids"] = args.scope_panids
    if args.scope_eui64s:
        cfg.setdefault("scope", {})["eui64s"] = args.scope_eui64s

    # Single-phase mode
    if args.phase:
        _all_phases = ["survey", "key_recovery", "enumeration", "attacks", "firmware"]
        cfg["phases"] = {k: (k == args.phase) for k in _all_phases}

    if not args.project:
        _cs = (cfg.get("client_short") or "").strip()
        _sd = (cfg.get("start_date") or "").strip()
        args.project = str(_build_project_dir(_cs, _sd, os.environ.get("SPECTRE_TOOL_ID", "aether-z")))

    project_dir = Path(args.project)
    project_dir.mkdir(parents=True, exist_ok=True)
    # §13b/§14j/§14k: canonical run-dir audit log + own-version startup EVENT.
    global _RUNLOG
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
            _RUNLOG.event(f"Aether-Z v{VERSION} started")
        except Exception:
            _RUNLOG = None

    global _PAUSE
    if _pp is not None:
        _PAUSE = _pp.PauseManager(str(project_dir), "aether-z")
        _PAUSE.start_watcher(grace_period=60)
        _resumed = os.environ.get("CRUCIBLE_RESUME") == "1"
        _PAUSE.log_run_type(resumed=_resumed)
        if _resumed:
            _PAUSE.cleanup_incomplete()

    _write_project_meta(
        project_dir,
        tool=os.environ.get("SPECTRE_TOOL_ID", "aether-z"),
        client_short=cfg.get("client_short", ""),
        year=((cfg.get("start_date") or "")[:4] or datetime.now(timezone.utc).strftime("%Y")),
        version=VERSION,
    )

    run(cfg, project_dir)


# ── Module-level catalogue load ───────────────────────────────────────────────
_load_catalogue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _log("Assessment interrupted by operator.")
        sys.exit(0)
