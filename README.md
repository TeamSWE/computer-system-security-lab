# Computer System Security Labs

Welcome to the **Computer System Security Labs** repository. This project contains practical laboratory assignments and hands-on security modules covering malware taxonomy, detection mechanisms, cryptographic integrity, system hardening, and defensive analysis.

## Repository Structure

```text
computer-system-security-lab/
├── README.md                 # Repository overview & lab directory index
├── .gitignore                # Global ignore rules (virtual environments, caches)
└── file-virus-lab/           # Lab 1: Python File Virus Simulation & Antivirus Detection
    ├── README.md             # Detailed lab guide & theoretical foundations (COMP 561)
    ├── requirements.txt      # Dependencies (Python standard library only)
    ├── virus_simulator.py    # Controlled file infection simulator
    ├── antivirus.py          # Passive signature scanner & SHA-256 reporter
    ├── integrity.py          # Cryptographic integrity monitoring tool
    ├── lab/                  # Dedicated lab fixtures, baselines, and backups
    ├── scripts/              # Setup, end-to-end demo, and restoration tools
    └── tests/                # Automated unit and safety test suite
```

---

## Lab Index

### [Lab 1: Python File Virus Simulation & Antivirus Detection Lab](file-virus-lab/)

- **Course Topic:** Malware Taxonomy, Host File Infection, Signature-Based Scanning, and Cryptographic Integrity Monitoring (COMP 561 Chapter 1).
- **Core Concepts:**
  - Difference between parasitic file viruses and autonomous network worms.
  - Transmission vectors (infected attachments, removable storage, compromised downloads).
  - Harmless signature marker appending simulation (`EDU_VIRUS_SIMULATION_MARKER_V1`).
  - Read-only antivirus signature scanning (`CLEAN`, `DETECTED`, `ERROR`).
  - SHA-256 cryptographic baseline recording and mismatch detection.
  - Reversible lab environment with automated restoration.
- **Quick Start:**
  ```bash
  cd file-virus-lab
  # Run the full 9-phase automated demonstration:
  python3 scripts/run_demo.py

  # Run the test suite:
  python3 -m unittest discover -s tests -v
  ```
  See the [file-virus-lab/README.md](file-virus-lab/README.md) for full instructions, theoretical background, and CLI usage.
