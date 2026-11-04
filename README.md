<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Aether-Z — ZigBee / IEEE 802.15.4 Penetration Test Orchestrator

> [!CAUTION]
> **Under Development — Untested.** This tool has not been validated in production engagements. Features may be incomplete, unstable, or produce unreliable results. Do not rely on its output for deliverables without independent verification.

**Version:** 1.0.0
**Author:** pr0t31n
**Platform:** Linux (Kali / Ubuntu recommended)

---

## Overview

Aether-Z is a multi-phase ZigBee security assessment orchestrator. It automates passive
RF discovery, network key recovery, active device enumeration, authenticated attack testing,
and firmware security analysis against IEEE 802.15.4 / ZigBee networks and devices.

Aether-Z integrates with the Crucible web platform via protocol tokens, allowing assessments
to be launched, monitored, and reviewed from the Crucible dashboard.

### Features

- **Phase 0 — RF Survey**: Passive channel scan using zbstumbler/zbfind. Discovers PAN-IDs,
  coordinator EUI64s, active channels, and join window status.
- **Phase 1 — Key Recovery**: Intercepts ZigBee network key transport frames during device
  join events using zbdsniff. Performs offline key extraction from captures via z3sec. Scans
  gateway configuration files (Zigbee2MQTT, Home Assistant) for plaintext keys.
- **Phase 2 — Enumeration**: Active ZDO enumeration with zbid and zbscapy. Identifies all
  endpoints, clusters, and device capabilities. Integrates with tshark for pcap decoding using
  recovered network keys.
- **Phase 3 — Attack Testing**: ZCL command replay (zbreplay), authenticated ZCL injection
  using recovered keys (zbscapy), ZLL touchlink steal and factory reset, and PAN-ID conflict /
  association flood DoS. All attack sub-phases are gated behind explicit authorisation flags.
- **Phase 4 — Firmware Analysis**: CC2531/CC253x flash extraction via goodfet.cc, generic JTAG
  dump via openocd, and static firmware analysis via binwalk for hardcoded keys and unsigned
  OTA upgrade cluster detection.
- **Crucible Integration**: All phases emit structured protocol tokens consumed by the Crucible
  web platform for real-time status, finding, and log display.
- **Findings Catalogue**: 15 documented findings (AETHZ-001 through AETHZ-015) with CVSS scores,
  category classifications, and actionable remediations.

---

## Hardware Requirements

### Minimum
- **CC2531 USB dongle** flashed with KillerBee firmware
  - Cheap and widely available; required for zbstumbler, zbdump, zbdsniff, zbid
  - Flash with: `cc-tool -e -w cc2531_zbstumbler.hex`

### Recommended
- **CC2531 x2**: one for passive sniffing, one for active injection
- **GoodFET**: for CC2530/CC2531 JTAG flash extraction (Phase 4)
- **Bus Pirate or J-Link**: for generic ARM JTAG with openocd (Phase 4)
- **HackRF One** (optional): for broadband 802.15.4 spectrum analysis and SDR fuzzing

### Supported chipsets (KillerBee)
- Texas Instruments CC2531, CC2530, CC2520
- ApiMote (GoodFET-based)
- Freakduino / Arduino with 802.15.4 radio shield

---

## Software Requirements

- Python 3.9+
- Linux kernel with USB support (usbcore, cp210x / cdc_acm drivers)
- KillerBee suite (zbstumbler, zbdump, zbdsniff, zbid, zbscapy, zbreplay, zbassocflood, zbfind)
- Z3sec (ZigBee / ZLL security analysis)
- tshark / Wireshark (with ZigBee dissectors)
- binwalk (firmware analysis)
- openocd (JTAG extraction)
- goodfet.cc (CC253x JTAG extraction)

All dependencies except goodfet are installed by `install.py`.

---

## Installation

### Quick install (Kali / Ubuntu)

```bash
cd /Users/pr0t31n/Aether-Z
sudo python3 install.py
```

### Dry-run (see what would be installed without making changes)

```bash
sudo python3 install.py --check
```

### Skip specific phases

```bash
sudo python3 install.py --skip-git      # Skip KillerBee / Z3sec clone
sudo python3 install.py --skip-apt      # Skip system packages
```

### Manual KillerBee install

```bash
git clone https://github.com/riverloopsec/killerbee /opt/killerbee
pip3 install -e /opt/killerbee
```

### Manual Z3sec install

```bash
git clone https://github.com/IoTsec/Z3sec /opt/z3sec
pip3 install -r /opt/z3sec/requirements.txt
```

---

## Usage

### Full assessment (all enabled phases)

```bash
sudo python3 aether_z.py --config config.json --project /path/to/project
```

### Single phase

```bash
sudo python3 aether_z.py --phase survey --interface /dev/ttyUSB0
sudo python3 aether_z.py --phase key_recovery --interface /dev/ttyUSB0
sudo python3 aether_z.py --phase enumeration --interface /dev/ttyUSB0 --channel 15
```

### Attack phases (require explicit authorisation)

```bash
sudo python3 aether_z.py --phase attacks \
    --interface /dev/ttyUSB0 \
    --network-key AABBCCDDEEFF00112233445566778899 \
    --injection-authorized

sudo python3 aether_z.py --phase attacks \
    --dos-authorized \
    --interface /dev/ttyUSB0
```

### Firmware phase (requires physical access)

```bash
sudo python3 aether_z.py --phase firmware \
    --physical-access
```

### Scope limiting

```bash
sudo python3 aether_z.py \
    --scope-panid 0x1A2B \
    --scope-panid 0x3C4D \
    --interface /dev/ttyUSB0
```

### List available phases

```bash
python3 aether_z.py --list-phases
```

### Pass known network keys for enumeration / decryption

```bash
sudo python3 aether_z.py --phase enumeration \
    --network-key AABBCCDDEEFF00112233445566778899 \
    --interface /dev/ttyUSB0
```

---

## Phase Descriptions

### Phase 0 — RF Environment Survey (`survey`)

Performs a passive channel scan across the configured IEEE 802.15.4 channels (default: 11,
15, 20, 25 — the ZigBee preferred channels). Uses zbstumbler to identify active PANs,
their coordinator EUI64 addresses, and whether the join window is open.

**Findings triggered:** AETHZ-010 (Permanently Open Join Window)

**Tools:** zbstumbler, zbfind (fallback)

**Output:** `<project>/aether_z_output/survey/`

### Phase 1 — Network Key Recovery (`key_recovery`)

Monitors ZigBee join events to intercept key transport frames. When the default Trust Center
Link Key (ZigBeeAlliance09) is in use, zbdsniff can passively recover the network encryption
key from a single join event. Also performs offline analysis of raw captures with z3sec and
scans the local filesystem for plaintext keys in gateway configuration files.

**Findings triggered:**
- AETHZ-001: Network key recovered via join intercept
- AETHZ-002: Default TCLK confirmed in use
- AETHZ-003: Plaintext key in gateway config file

**Tools:** zbdsniff, zbdump, z3sec

**Output:** `<project>/aether_z_output/key_recovery/`

### Phase 2 — Active Enumeration (`enumeration`)

Performs ZDO queries to enumerate all devices, endpoints, and clusters on discovered networks.
Uses zbid for device identification and zbscapy for cluster-level enumeration. Optionally
decodes existing captures with tshark using recovered network keys for deeper traffic analysis.

**Findings triggered:** AETHZ-011 (Unauthenticated ZDO Enumeration)

**Tools:** zbid, zbscapy, tshark

**Output:** `<project>/aether_z_output/enumeration/`

### Phase 3 — Attack Testing (`attacks`)

**Requires: `injection_authorized: true` and/or `dos_authorized: true` in config.**

Sub-phases:
- **Replay (3a):** Captures and replays ZCL command frames using zbreplay to test frame
  counter enforcement.
- **Injection (3b):** Crafts and sends authenticated ZCL frames using a recovered network
  key via zbscapy. Tests command injection into On/Off, Door Lock, and IAS clusters.
- **Touchlink (3c):** Scans for ZLL devices and attempts touchlink steal and factory reset
  using the leaked ZLL Master Key.
- **DoS (3d):** PAN-ID conflict flood and association flood to test network resilience.

**Findings triggered:**
- AETHZ-004: Replay attack successful
- AETHZ-005: ZCL command injection successful
- AETHZ-006: ZLL device stolen
- AETHZ-007: ZLL factory reset accepted
- AETHZ-008: Network DoS successful
- AETHZ-015: ZLL Master Key deployment confirmed

**Tools:** zbreplay, zbscapy, zbassocflood, zbpanidconflictflood

**Output:** `<project>/aether_z_output/attacks/`

### Phase 4 — Firmware Analysis (`firmware`)

**Requires: `physical_access: true` in config (for hardware extraction sub-phases).**

Sub-phases:
- **goodfet.cc (4a):** Extracts CC2531/CC2530 firmware via JTAG using a GoodFET device.
- **openocd (4b):** Extracts firmware from ARM-based ZigBee devices via JTAG.
- **binwalk (4c):** Static analysis of firmware binaries for embedded ZigBee keys,
  ZLL Master Key presence, and unsigned OTA upgrade cluster detection.

**Findings triggered:**
- AETHZ-009: Key extracted from firmware via JTAG
- AETHZ-012: Hardcoded keys in firmware binary
- AETHZ-013: Unsigned OTA firmware updates

**Tools:** goodfet.cc, openocd, binwalk

**Output:** `<project>/aether_z_output/firmware/`

---

## Configuration Guide

The `config.json` file controls all assessment parameters:

| Field                   | Type         | Description                                              |
|-------------------------|--------------|----------------------------------------------------------|
| `interface`             | string       | ZigBee USB dongle device path (e.g. `/dev/ttyUSB0`)     |
| `channel`               | int or null  | Lock to a single channel; null = scan all channels      |
| `channels`              | array[int]   | Channels to scan (ZigBee preferred: 11, 15, 20, 25)     |
| `target_panids`         | array[str]   | Limit to specific PAN-IDs (e.g. `["0x1A2B"]`)           |
| `target_eui64s`         | array[str]   | Limit to specific device EUI64s                         |
| `timeout_per_phase`     | int          | Per-phase timeout in seconds (default: 300)             |
| `capture_duration`      | int          | Max capture duration in seconds (default: 3600)         |
| `phases.survey`         | bool         | Enable RF survey phase                                   |
| `phases.key_recovery`   | bool         | Enable key recovery phase                               |
| `phases.enumeration`    | bool         | Enable enumeration phase                                |
| `phases.attacks`        | bool         | Enable attack phase                                      |
| `phases.firmware`       | bool         | Enable firmware analysis phase                          |
| `network_keys`          | array[str]   | Known network keys (32-char hex) for enumeration/attack |
| `known_tclk`            | string       | Trust Center Link Key to test against                   |
| `zll_master_key`        | string       | ZLL Master Key for touchlink attacks                    |
| `injection_authorized`  | bool         | Must be true to enable injection sub-phases             |
| `dos_authorized`        | bool         | Must be true to enable DoS sub-phases                   |
| `physical_access`       | bool         | Must be true to enable JTAG hardware extraction         |
| `scope.panids`          | array[str]   | Scope whitelist: only attack these PAN-IDs              |
| `scope.eui64s`          | array[str]   | Scope whitelist: only target these EUI64s               |
| `output_dir`            | string       | Subdirectory under project root for all output          |

---

## Crucible Integration

When Aether-Z is launched by the Crucible platform (environment variable `CRUCIBLE_MANAGED=1`),
all output uses structured protocol tokens:

```
__SPECTRE_LOG__    <plain text log message>
__SPECTRE_ERR__    <plain text error message>
__SPECTRE_STATUS__ {"phase": "...", "status": "running|complete|skipped|error", "step": "...", "ts": "..."}
__SPECTRE_FINDING__ {"id": "AETHZ-001", "title": "...", "severity": "CRITICAL", ...}
__SPECTRE_PROMPT__ <message requiring operator confirmation>
```

Crucible parses these tokens in real-time to display phase status, populate the findings table,
and stream logs to the operator interface. The `CRUCIBLE_MANAGED` environment variable is set
automatically when Crucible launches Aether-Z as a subprocess.

---

## Output Structure

After an assessment, the project directory contains:

```
<project>/
  aether_z_output/
    assessment_meta.json        — Assessment metadata and summary
    findings_spectre.json       — All findings in Spectre format
    survey/
      zbstumbler_ch11.txt       — zbstumbler output per channel
      zbstumbler_ch15.txt
      discovered_pans.json      — Structured PAN discovery results
    key_recovery/
      zbdsniff_ch11.txt         — zbdsniff capture/output
      zbdump_ch11.pcap          — Raw IEEE 802.15.4 capture
      z3sec_ch11.txt            — z3sec analysis output
      recovered_keys.json       — All recovered key material
    enumeration/
      zbid_ch11.txt             — zbid device enumeration
      zbscapy_ch11.txt          — zbscapy cluster enumeration
      tshark_zbdump_ch11.txt    — tshark decoded frames
      devices_found.json        — Structured device inventory
    attacks/
      zbreplay_zbdump_ch11.txt  — Replay attack output
      inject_ch11.txt           — Injection test output
      zll_touchlink.txt         — ZLL touchlink output
      panid_flood_ch11.txt      — PAN-ID flood output
      assoc_flood_ch11.txt      — Association flood output
    firmware/
      cc253x_flash.bin          — goodfet.cc extracted firmware
      openocd_flash.bin         — openocd extracted firmware
      binwalk_cc253x_flash.txt  — binwalk analysis output
      binwalk_extract_*/        — Extracted firmware contents
```

---

## Legal Warning

**AUTHORIZED USE ONLY.**

Aether-Z is designed exclusively for use on ZigBee networks and devices where you have
explicit written authorization from the device/network owner. Unauthorized interception
of ZigBee traffic, injection of ZigBee frames, or extraction of firmware from devices
you do not own may violate the Computer Fraud and Abuse Act (CFAA), the Electronic
Communications Privacy Act (ECPA), and equivalent legislation in other jurisdictions.

The attack phases (Phase 3) are disabled by default and require explicit `injection_authorized`
and `dos_authorized` flags. The firmware phase (Phase 4) hardware extraction sub-phases require
`physical_access: true`. These safeguards exist to prevent accidental unauthorized testing.

The authors and contributors of Aether-Z accept no liability for misuse.

---

## Credits

- **KillerBee** — Ryan Speelman, Ryan Holeman, River Loop Security
  https://github.com/riverloopsec/killerbee
- **Z3sec** — IoTsec Research
  https://github.com/IoTsec/Z3sec
- **ZigBee Specification** — Connectivity Standards Alliance
  https://csa-iot.org
- **Dragonblood ZigBee research** — Cognosec GmbH
- **Aether-Z** — pr0t31n (modelled after Aether wireless assessment framework)
