# Python File Virus Simulation & Antivirus Detection Lab

**Course Reference:** Computer System Security (COMP 561 Chapter 1)  
**Academic Level:** University Undergraduate / Graduate Security Laboratory  
**Implementation Language:** Python 3 (Standard Library Only, `>= 3.10`)  
**Safety Classification:** Strictly Controlled Inert Simulation — Non-Malicious, Non-Replicating

---

## 1. Project Overview & Objectives

In modern computer system security, understanding how file-infecting malware modifies host artifacts and how defensive software identifies such tampering is foundational. This educational laboratory project implements two complementary components:

1. **File Infection Simulator (`virus_simulator.py`):** Models the parasitic appending behavior of a traditional file virus by adding an inert, recognizable educational signature marker (`EDU_VIRUS_SIMULATION_MARKER_V1`) to an authorized `.txt` target file in a strictly bounded, reversible environment.
2. **Antivirus Detector (`antivirus.py`):** Demonstrates signature-based detection by passively inspecting target files for the simulation marker, calculating cryptographic checksums (SHA-256), and reporting deterministic classification statuses (`CLEAN`, `DETECTED`, `ERROR`).
3. **File Integrity Monitor (`integrity.py`):** Demonstrates cryptographic baseline monitoring by storing and comparing SHA-256 digests to identify unauthorized bit alterations regardless of signature matches.
4. **Automated Verification & Restoration Suite:** Provides unit testing covering simulation mechanics, passive detection, integrity baselining, and rigorous safety constraints, coupled with clean environment restoration scripts.

---

## 2. Theoretical Foundations (COMP 561 Chapter 1)

### 2.1 File Viruses vs. Network Worms

| Dimension | File Virus | Computer Worm |
| :--- | :--- | :--- |
| **Host Requirement** | **Parasitic:** Requires an existing host file (binary executable, script, or document macro) to survive and execute. | **Self-Contained:** Standalone executable or process that does not require an existing host file. |
| **Activation Vector** | **User-Triggered:** Activated when a user or system executes the host program or opens an infected document. | **Autonomous:** Exploits network services, unpatched daemon vulnerabilities, or weak credentials without human intervention. |
| **Propagation Mode** | Carried across systems via shared files, email attachments, or removable storage devices. | Actively probes networks, scans IP address ranges, and transmits itself across open ports (e.g., Morris Worm, Code Red). |
| **Infection Mechanics** | Prepender, Appender, or Cavity infector modifying host file headers or code segments. | Direct memory injection, buffer overflow exploitation, and independent process creation. |

### 2.2 Common Virus Transmission Vectors

1. **Infected Email Attachments:** Malicious payloads packaged as executable attachments (`.exe`, `.scr`, `.vbs`) or weaponized documents containing macros (`.docm`, `.xlsm`) using social engineering to induce user execution.
2. **Removable Media (USB / External Drives):** Physical propagation utilizing OS autorun mechanisms or deceptive file shortcuts (`.lnk`) that execute malware when external media is inserted.
3. **Compromised Downloads & Drive-By Downloads:** Unofficial download mirrors, cracked software distributions, and compromised web servers injecting malicious stagers into legitimate software installers.
4. **Permissive Network Shares:** Network folders with unauthenticated write permissions allowing an infected endpoint to append malicious code to shared executables.

### 2.3 Potential Impacts & Harms of Malicious Infection

- **Data Corruption & Alteration (Integrity Loss):** Silent modification of system databases, documents, and code repositories, degrading data reliability.
- **Unauthorized Exfiltration (Confidentiality Loss):** Secondary payloads installing keyloggers, screen grabbers, or credential stealers targeting sensitive authentication tokens.
- **System Downtime (Availability Loss):** Destructive payload execution, master boot record (MBR) wiping, or ransomware encryption depriving users of computing services.
- **Resource Exhaustion:** Denial of service caused by runaway background threads, memory leaks, and CPU starvation.

---

## 3. Defensive Concepts: Signatures vs. Integrity Monitoring

### 3.1 Signature-Based Detection & The Simulation Marker

A **virus signature** is a unique, statistically identifiable sequence of bytes or text patterns characteristic of a specific malware variant. Antivirus engines compare files against extensive signature definition databases.

In this lab, the known signature is defined as:
```text
EDU_VIRUS_SIMULATION_MARKER_V1
```
When `virus_simulator.py` simulates an infection, it appends this inert marker to the target file. The `antivirus.py` scanner looks for this exact byte sequence. If present, it assigns the status `[DETECTED]`.

#### Critical Limitations of Signature Scanning:
- **Zero-Day Vulnerability:** New or previously uncataloged malware variants have no existing signature and bypass detection entirely.
- **Polymorphism and Metamorphism:** Advanced malware employs encryption routines with randomized keys or rewrites its instruction sequence on each infection, rendering static byte signatures obsolete.
- **Packers and Obfuscation:** Runtime packers (e.g., UPX, custom crypters) conceal underlying executable code until loaded into memory.

### 3.2 Cryptographic Integrity Monitoring (SHA-256)

An integrity monitor calculates cryptographic hashes (such as SHA-256) of critical system files when the system is known to be in a pristine state (the **baseline**). 

The SHA-256 hash function satisfies three fundamental cryptographic security properties:
1. **Pre-image Resistance (One-Way):** Given a hash $h$, it is computationally infeasible to find message $m$ such that $\text{SHA-256}(m) = h$.
2. **Second Pre-image Resistance (Weak Collision Resistance):** Given an input $m_1$, it is computationally infeasible to find $m_2 \neq m_1$ such that $\text{SHA-256}(m_1) = \text{SHA-256}(m_2)$.
3. **Collision Resistance (Strong Collision Resistance):** It is computationally infeasible to find any pair of distinct inputs $(m_1, m_2)$ such that $\text{SHA-256}(m_1) = \text{SHA-256}(m_2)$.

#### Important Educational Distinction: Integrity Change $\neq$ Malware Detection
> [!IMPORTANT]
> A cryptographic checksum mismatch confirms **that** a file changed, but **cannot explain why** it changed.
> - **Benign Alterations:** Authorized software patches, user edits, and automatic timestamp updates alter the file's hash just as completely as a virus infection.
> - **Malware Alterations:** Malicious code injection also alters the hash.
> 
> Therefore, integrity monitoring acts as an **anomaly detection sensor**, alerting administrators to unexpected changes that warrant forensic investigation, while signature scanning aims to confirm **specific, recognized threats**.

---

## 4. Project Directory Structure

```text
file-virus-lab/
├── README.md                           # Comprehensive documentation and lab manual
├── requirements.txt                    # Project dependencies (Python standard library only)
├── .gitignore                          # Exclusions for virtual environments, caches, and backups
├── virus_simulator.py                  # Component A: Safe, idempotent file infection simulator
├── antivirus.py                        # Component B: Passive signature scanner and SHA-256 reporter
├── integrity.py                        # Component C: Cryptographic integrity baseline & comparison tool
├── lab/                                # Strictly confined lab working directory
│   ├── README.md                       # Guide to lab containment and fixture roles
│   ├── targets/                        # Approved target text files
│   │   ├── clean_sample.txt            # Pristine test file (plain educational text)
│   │   ├── sample_document.txt         # Security principles reference text
│   │   └── simulated_infected_sample.txt # Static fixture containing simulation marker
│   ├── baselines/                      # Baseline profile storage
│   │   ├── .gitkeep
│   │   └── integrity_baselines.json    # JSON baseline database
│   ├── quarantine/                     # Reserved directory for isolated artifacts
│   │   └── .gitkeep
│   └── backups/                        # Pre-modification backups created by the simulator
│       └── .gitkeep
├── scripts/
│   ├── create_test_files.py            # Generates fresh pristine test target files
│   ├── run_demo.py                     # Automated 9-stage end-to-end demonstration
│   └── restore_lab.py                  # Restoration script resetting lab to pristine state
└── tests/
    ├── __init__.py                     # Package marker for unittest discovery
    ├── test_simulator.py               # Unit tests for simulator mechanics & confinement
    ├── test_antivirus.py               # Unit tests for passive scanner accuracy & read-only enforcement
    ├── test_integrity.py               # Unit tests for hash verification & baseline protection
    └── test_safety.py                  # Safety tests verifying zero network/subprocess/outside access
```

---

## 5. Safety Architecture & Safeguards

The project strictly follows defense-in-depth safety design principles:

1. **Path Canonicalization & Confinement:** All target paths are converted to absolute canonical forms using `pathlib.Path.resolve()`. Any path resolving outside `lab/targets/` is rejected with `SecurityValidationError`.
2. **Symlink Escape Defense:** Symbolic links resolving outside `lab/targets/` are rejected.
3. **File Extension Restriction:** Only `.txt` files are permitted. Python source files (`.py`), shell scripts (`.sh`), executables, and binaries are rejected.
4. **Prohibition of Code Execution:** Neither the simulator nor detector executes, imports, or runs target files.
5. **Single-File Idempotency:** The simulator operates only on the explicitly supplied file (no directory traversal or recursion) and refuses to re-infect files that already contain the simulation marker.
6. **Automatic Backups:** The simulator copies original files to `lab/backups/` before applying modifications.
7. **Zero Side-Effects:** No network sockets, subprocesses, cron jobs, registry keys, or environment files are touched.

---

## 6. Installation & Prerequisites

This project requires **Python 3.10 or newer** and uses **only the Python standard library**. No third-party packages (e.g., `pip install`) are required.

```bash
# Clone or navigate to the repository
cd file-virus-lab

# Verify Python version (must be >= 3.10)
python3 --version
```

---

## 7. Command-Line Interface & Usage Guide

### 7.1 Inspect a Clean File (Antivirus Scan)
Scan an uninfected test file using the passive signature detector:
```bash
python3 antivirus.py lab/targets/clean_sample.txt
```
**Expected Output:**
```text
======================================================================
      EDUCATIONAL ANTIVIRUS SIGNATURE SCANNER
======================================================================
Target File:      clean_sample.txt
Path:             .../lab/targets/clean_sample.txt
Scan Result:      [CLEAN]
----------------------------------------------------------------------
File Size:        804 bytes
Last Modified:    2026-10-26 10:51:21 UTC
SHA-256 Digest:   56c1cd361c1d1f74fe62dde096dea9cf55d719f533fdfb3d337d52e3393a8a5d
Marker Detected:  False
Scan Details:     No known simulation signatures identified in target file.
======================================================================
```
*Exit Code:* `0` (`CLEAN`)

---

### 7.2 Create an Integrity Baseline
Record a trusted SHA-256 cryptographic baseline before any modifications:
```bash
python3 integrity.py baseline lab/targets/clean_sample.txt
```
**Expected Output:**
```text
[✓] SUCCESS: Baseline successfully recorded for 'clean_sample.txt'.
    File:     clean_sample.txt
    SHA-256:  56c1cd361c1d1f74fe62dde096dea9cf55d719f533fdfb3d337d52e3393a8a5d
    Size:     804 bytes
```
*Note:* Re-running without `--force` will be rejected to protect baseline integrity.

---

### 7.3 Simulate a Controlled File Modification
Append the harmless educational simulation marker to the authorized test file:
```bash
python3 virus_simulator.py lab/targets/clean_sample.txt
```
**Expected Output:**
```text
======================================================================
      EDUCATIONAL FILE VIRUS SIMULATION REPORT
======================================================================
Target File:      clean_sample.txt
Full Path:        .../lab/targets/clean_sample.txt
Action:           APPEND SIMULATION MARKER
Status:           SIMULATION_APPLIED
----------------------------------------------------------------------
Original Size:    804 bytes
Original SHA-256: 56c1cd361c1d1f74fe62dde096dea9cf55d719f533fdfb3d337d52e3393a8a5d
Modified Size:    1113 bytes (+309 bytes)
Modified SHA-256: 90a9d846c790c5bdc0bb1aac2275d3a727c9c0b9317d5ec48a807d56fe37aa59
Backup Location:  .../lab/backups/clean_sample.txt.bak
----------------------------------------------------------------------
Summary: Simulated infection marker appended successfully. Backup stored at clean_sample.txt.bak.
======================================================================
```
*Exit Code:* `0`

---

### 7.4 Test Idempotency (Re-infection Refusal)
Attempting to run the simulator again on the modified target:
```bash
python3 virus_simulator.py lab/targets/clean_sample.txt
```
**Expected Output:**
```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!] IDEMPOTENCY REFUSAL:
File 'clean_sample.txt' already contains the simulation marker 'EDU_VIRUS_SIMULATION_MARKER_V1'.
Infection refused: The simulator is idempotent and will not re-infect files.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```
*Exit Code:* `2`

---

### 7.5 Dry-Run Simulation (No Changes Made)
Inspect proposed modifications without writing to disk:
```bash
python3 virus_simulator.py --dry-run lab/targets/sample_document.txt
```

---

### 7.6 Detect the Simulated Infection (Antivirus Scan)
Scan the modified file to detect the marker:
```bash
python3 antivirus.py lab/targets/clean_sample.txt
```
**Expected Output:**
```text
======================================================================
      EDUCATIONAL ANTIVIRUS SIGNATURE SCANNER
======================================================================
Target File:      clean_sample.txt
Path:             .../lab/targets/clean_sample.txt
Scan Result:      [DETECTED]
----------------------------------------------------------------------
File Size:        1113 bytes
Last Modified:    2026-10-26 10:51:28 UTC
SHA-256 Digest:   90a9d846c790c5bdc0bb1aac2275d3a727c9c0b9317d5ec48a807d56fe37aa59
Marker Detected:  True
Scan Details:     Educational signature match: 'EDU_VIRUS_SIMULATION_MARKER_V1' identified.
======================================================================
```
*Exit Code:* `1` (`DETECTED`)

---

### 7.7 Verify File Integrity Warning
Compare the modified target's current hash against the recorded baseline:
```bash
python3 integrity.py check lab/targets/clean_sample.txt
```
**Expected Output:**
```text
======================================================================
         FILE INTEGRITY MONITORING REPORT
======================================================================
Target:           clean_sample.txt
Path:             .../lab/targets/clean_sample.txt
Verification:     [MISMATCH]
----------------------------------------------------------------------
Status:           WARNING - INTEGRITY COMPROMISED (CHANGED)
Baseline SHA-256: 56c1cd361c1d1f74fe62dde096dea9cf55d719f533fdfb3d337d52e3393a8a5d
Current SHA-256:  90a9d846c790c5bdc0bb1aac2275d3a727c9c0b9317d5ec48a807d56fe37aa59
Baseline Size:    804 bytes
Current Size:     1113 bytes
======================================================================
```
*Exit Code:* `1` (`MISMATCH`)

---

### 7.8 Restore the Environment
Safely restore the lab fixtures to their pristine clean state and clean up temporary backups:
```bash
python3 scripts/restore_lab.py
```
**Expected Output:**
```text
====================================================================
      EDUCATIONAL LAB ENVIRONMENT RESTORATION TOOL
====================================================================
[+] Created clean_sample.txt (804 bytes) | SHA-256: 56c1cd361c1d1f74...
[+] Created sample_document.txt (1292 bytes) | SHA-256: f1473372ab8a7492...
[+] Created simulated_infected_sample.txt (618 bytes) | SHA-256: 66646a4536290a56...
Restoring lab targets in: .../lab/targets
Cleaned 2 backup file(s): clean_sample.txt.bak, clean_sample_20261026_135128.txt.bak
[✓] Verified clean_sample.txt matches pristine baseline (56c1cd361c1d1f74...)
[✓] Verified sample_document.txt matches pristine baseline (f1473372ab8a7492...)
[✓] Verified simulated_infected_sample.txt matches pristine baseline (66646a4536290a56...)

[✓] Lab environment successfully restored to pristine clean state.
```

---

## 8. Automated Demonstration Workflow

The repository includes an automated 9-phase demonstration script executing the complete lifecycle:
```bash
python3 scripts/run_demo.py
```

**Demonstration Sequence:**
1. Initialize pristine test target (`clean_sample.txt`).
2. Record initial cryptographic checksum & register integrity baseline.
3. Perform initial Antivirus scan (`CLEAN`).
4. Execute simulated file virus infection (marker appended, backup saved).
5. Perform Antivirus scan on modified target (`DETECTED`).
6. Perform File Integrity Monitor verification (`MISMATCH`).
7. Restore target from verified backup.
8. Perform Antivirus scan on restored target (`CLEAN`).
9. Verify restored file cryptographic hash matches original baseline (`MATCH`).

---

## 9. Automated Testing Suite

All tests are implemented using Python's built-in `unittest` module and execute inside isolated temporary sandboxes (`tempfile.TemporaryDirectory`).

Execute the entire test suite with:
```bash
python3 -m unittest discover -s tests -v
```

### Test Coverage Summary:
- **`tests/test_simulator.py` (8 tests):**
  - Clean target infection mechanics
  - Single marker enforcement
  - Idempotency and re-infection prevention
  - Backup creation and restoration validation
  - Dry-run non-modification guarantee
  - Rejection of unsupported extensions (`.py`, `.exe`, `.bin`, `.sh`)
  - Directory traversal prevention (`../../`)
  - Symlink escape prevention
- **`tests/test_antivirus.py` (5 tests):**
  - Detection of clean targets (`CLEAN`, exit 0)
  - Detection of infected targets (`DETECTED`, exit 1)
  - Missing file handling (`ERROR`, exit 2)
  - Out-of-scope path rejection (`ERROR`, exit 2)
  - Strict read-only guarantee (file hash/size/mtime unmodified)
- **`tests/test_integrity.py` (5 tests):**
  - SHA-256 calculation determinism
  - Baseline creation and successful `MATCH`
  - Bit modification detection producing `MISMATCH`
  - Baseline overwrite protection (`--force` requirement)
  - Baseline path traversal prevention
- **`tests/test_safety.py` (5 tests):**
  - Zero modifications permitted outside `lab/targets/`
  - Network socket prohibition (mocked socket verification)
  - Subprocess and shell command prohibition (`os.system`, `subprocess.Popen`)
  - Persistence and startup modification prevention
  - No deletion or auto-quarantine by scanner

---

## 10. Ethical and Safe Lab-Use Statement

This software is developed strictly for **academic and educational purposes** as part of university coursework in computer system security. 

- **Controlled Environment:** All simulations are confined to synthetic text documents within the `lab/targets/` directory.
- **No Malicious Capability:** The simulator does not self-replicate, does not propagate across networks, does not execute payloads, and does not alter executable software or operating system components.
- **Academic Responsibility:** Students and researchers must never apply infection techniques, even simulated ones, to production systems or files belonging to other users without explicit authorization.
