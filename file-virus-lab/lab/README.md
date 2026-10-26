# Educational Security Lab Directory (`lab/`)

This directory is the **strictly isolated working area** for all file-infection simulations and antivirus signature detection exercises.

## 1. Directory Structure

```text
lab/
├── README.md               # This documentation file
├── targets/                # Authorized test text files
│   ├── clean_sample.txt                # Pristine clean test target
│   ├── sample_document.txt             # Reference document on malware principles
│   └── simulated_infected_sample.txt   # Static fixture containing the simulation marker
├── baselines/              # Cryptographic integrity baselines
│   ├── .gitkeep
│   └── integrity_baselines.json        # Recorded SHA-256 baseline profiles
├── quarantine/             # Reserved for isolated suspicious artifacts
│   └── .gitkeep
└── backups/                # Pre-modification backups created by the simulator
    └── .gitkeep
```

## 2. Directory Roles & Safety Boundaries

### `targets/`
- Contains **only non-executable, ordinary UTF-8 text files** (`.txt`).
- The simulator (`virus_simulator.py`) enforces strict validation and will **refuse** to operate on any file outside this directory.
- `simulated_infected_sample.txt` is an inert static fixture containing `EDU_VIRUS_SIMULATION_MARKER_V1` for baseline antivirus testing. It has no executable code or malicious logic.

### `baselines/`
- Holds the trusted reference checksum database (`integrity_baselines.json`) managed by `integrity.py`.
- Baselines record the canonical SHA-256 hash, byte size, and timestamp of trusted files.
- Overwriting existing baselines requires explicit user authorization (`--force`).

### `quarantine/`
- A dedicated isolation directory. In this educational lab, antivirus scanning is purely passive and read-only, so no files are deleted or moved automatically. This directory is reserved for manual quarantine exercises if extended.

### `backups/`
- When `virus_simulator.py` executes on a target, it automatically creates a pre-modification backup copy here (`<filename>.bak` and timestamped variants).
- `scripts/restore_lab.py` uses verified clean definitions to restore targets and purge runtime backups.

## 3. Strict Safety Protocol

1. **No External Modifications:** The simulator and scanner will never alter, inspect, or delete files outside the `lab/` tree.
2. **Read-Only Scanner:** The antivirus detector (`antivirus.py`) never modifies, moves, or deletes scanned targets.
3. **Pristine State Restoration:** The environment can be reset to clean state at any time via:
   ```bash
   python scripts/restore_lab.py
   ```
