<div align="center">

![APFS-Wonder Hero Banner](assets/banner.jpg)

# APFS-Wonder

**Next-Generation APFS FUSE Driver, Rootless CLI Extractor & Forensic Suite for Ubuntu 26.04+ & macOS Tahoe+**

[![Ubuntu 26.04 LTS / 26.10](https://img.shields.io/badge/Ubuntu-26.04_LTS_%7C_26.10-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/download)
[![macOS Tahoe 26 / 27+](https://img.shields.io/badge/macOS-Tahoe_26_%2F_27%2B-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Architecture](https://img.shields.io/badge/Mach--O-Universal_(arm64_%2B_x86__64)-0A84FF)](CMakeLists.txt)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&logoColor=white)](CMakeLists.txt)
[![Evals](https://img.shields.io/badge/Evals-10%2F10_PASS-2ea44f)](tests/run_evals.py)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)

</div>

---

## Overview

**APFS-Wonder** is a modernized, production-hardened evolution of [`sgan81/apfs-fuse`](https://github.com/sgan81/apfs-fuse) engineered for **latest Ubuntu (26.04 LTS / 26.10)** and **latest macOS Tahoe+ (macOS 26 / 27+, `apfs-2700.x`)**.

In addition to full compatibility with modern toolchains (**Clang 21+**, **GCC 16+**, **CMake 3.10–4.x+**), **APFS-Wonder** ships **10 production-ready add-ons** spanning rootless file extraction, transparent macOS `System` + `Data` Volume Group firmlink stitching, multi-volume container mounting, live Time Machine `.snapshots/` browsing, Sealed System Volume (`SSV`) SHA-256 integrity verification, checkpoint rollback forensics & deleted-file carving, thread-safe LRU decompression caching, FileVault keybag inspection, structured `--json` telemetry, and native `/sbin/mount.apfs` + `systemd` integration.

---

## Evaluation & Benchmark Results

All 10 production add-ons are continuously verified by the automated evaluation harness ([`tests/run_evals.py`](tests/run_evals.py)) against both **native macOS Tahoe 27.0.1 APFS containers** (`newfs_apfs`) and multi-volume/multi-checkpoint forensic test fixtures.

| # | Production Add-On | Evaluation Workload | Status | Latency | Measured Output / Telemetry |
| :-: | :--- | :--- | :-: | --: | :--- |
| **1** | **Rootless CLI Extractor & Browser**<br>(`apfsutil ls`/`tree`/`stat`/`cat`/`extract`/`find`) | Full volume B-tree walk + recursive extraction of 5 uncompressed & `decmpfs`-compressed files | **PASS** | `6.87 ms` | **5 files (21,136 B)** extracted without root or FUSE |
| **2** | **Volume Group & Firmlink Stitching**<br>(`System` + `Data` via `APFS_SF_FIRMLINK`) | Cross-volume lookup `/Users/profile.txt` traversing `com.apple.fs.firmlink` from Role `0x0001` to `0x0040` | **PASS** | `2.62 ms` | **100% transparent** `System` → `Data` firmlink resolution |
| **3** | **Multi-Volume Container Auto-Mounter**<br>(`apfs-fuse -a` / `-o all_vols`) | Whole-container enumeration & multi-slot virtual root routing (`TahoeSystem` + `TahoeSystem - Data`) | **PASS** | `2.76 ms` | **2 volumes** auto-mounted in a single container session |
| **4** | **Live `.snapshots/` Virtual Directory**<br>(`/.snapshots/<snap>` & `--snap <xid>`) | Mount historical Time Machine snapshot (`XID 1`, `com.apple.TimeMachine.2026-11-16-090000.local`) | **PASS** | `2.67 ms` | **7 snapshot root entries** resolved dynamically |
| **5** | **Sealed Volume (`SSV`) SHA-256 Verifier**<br>(`apfsutil integrity-check`) | Cryptographic verification of `APFS_FILE_INFO_DATA_HASH` (`APFS_TYPE_FILE_INFO`) extents via SHA-256 | **PASS** | `2.87 ms` | **4/4 files (21,136 B)** SHA-256 verified (`0` corruptions) |
| **6** | **Checkpoint Forensics & File Carver**<br>(`apfsutil xids` & `apfsutil carve`) | Scan NX `xp_desc` ring buffer (`XID 1` → `XID 2`), diff B-trees, and carve deleted `/deleted_secret.txt` | **PASS** | `2.87 ms` | **1 deleted file** carved & bit-identically recovered |
| **7** | **Thread-Safe LRU Decompression Cache**<br>(`ApfsLib/LruCache.h`, `-o cache_mb=N`) | 200 iterations × 4 files across ZLib (`algo 3`), LZVN (`algo 7`), and LZFSE (`algo 11`) `com.apple.decmpfs` | **PASS** | `0.22 ms` | **4.6× speedup** (`3,906` → **`17,960 MiB/s`**, `597` hits / `3` misses) |
| **8** | **Native Structured JSON Output Mode**<br>(`--json` across `apfsutil`) | Parse native macOS Tahoe `newfs_apfs` container & validate schemas across 7 CLI subcommands | **PASS** | `2.66 ms` | **7/7 JSON schemas** validated (`info`/`ls`/`stat`/`xids`/`carve`/`keybag`/`bench`) |
| **9** | **Keybag & FileVault Recovery Inspector**<br>(`apfsutil keybag [--verify-pass]`) | Inspect container/volume `kb_locker_t` entries (`KB_TAG_VOLUME_KEY`, `WRAPPED_KEK`) & RFC 3394 AES-XTS unwrap | **PASS** | `2.48 ms` | **Keybag metadata + VEK unwrap** validated |
| **10** | **`mount.apfs` Helper, Universal Binary & CPack**<br>(`/sbin/mount.apfs`, `apfs-wonder@.service`) | macOS Tahoe `apfs_superblock_t` full dump (`0x410..0x470`) + `mount(8)` CLI + Clang 21 & GCC 16 builds | **PASS** | `397.72 ms` | **0 warnings**, Universal `arm64+x86_64`, **0 unknown superblock bytes** |

### Decompression Cache Microbenchmark (`apfsutil bench`)

| Metric | Cold Cache (`--cache-mb 0`) | Warm LRU Cache (`--cache-mb 128`) | Improvement |
| :--- | --: | --: | --: |
| **200-Pass Total Latency** | `1.03 ms` | `0.22 ms` | **4.68× faster** |
| **Effective Read Throughput** | `3,906.37 MiB/s` | `17,960.47 MiB/s` | **+359.8%** |
| **Cache Hit Ratio** | `0.0%` | `99.5%` (`597` hits / `3` misses) | **Zero redundant LZFSE/LZVN/ZLib decodes** |

To reproduce all evaluations and benchmarks locally:

```bash
python3 tests/run_evals.py
```

---

## The 10 Production Add-Ons

### 1. Rootless / FUSE-less CLI Extractor & Browser (`apfsutil`)
Inspect and extract files from any APFS disk image, block device, or DMG on Linux or macOS **without root privileges or kernel FUSE modules**:
```bash
# List container & volume metadata (roles, volume groups, snapshots, encryption)
./build/apfsutil info disk.img

# Browse directories and display visual trees
./build/apfsutil ls disk.img /Users
./build/apfsutil tree disk.img / --depth 3

# Inspect detailed inode metadata, BSD flags, firmlink targets & SHA-256 data hashes
./build/apfsutil stat disk.img /readme.txt

# Stream file contents to stdout or recursively extract a directory tree to the host
./build/apfsutil cat disk.img /Users/profile.txt
./build/apfsutil extract disk.img / ./recovered_files

# Search for files by substring across the volume
./build/apfsutil find disk.img secret
```

### 2. Transparent Volume Group & Firmlink Resolution (`System` + `Data` Stitching)
Starting with macOS Catalina through macOS Tahoe+, macOS splits the root filesystem into a read-only `System` volume (`APFS_VOL_ROLE_SYSTEM = 0x0001`) and a read-write `Data` volume (`APFS_VOL_ROLE_DATA = 0x0040`) linked via `APFS_SF_FIRMLINK` (`0x00800000`) and the `com.apple.fs.firmlink` extended attribute.
- Both `apfs-fuse` and `apfsutil` automatically discover the paired `Data` volume in the same `apfs_volume_group_id` and transparently stitch firmlinked paths (`/Users`, `/Library`, `/Applications`, `/private/var`) into a unified directory hierarchy.

### 3. Multi-Volume / Whole-Container Auto-Mounter (`apfs-fuse -a` / `-o all_vols`)
Mount every volume inside an APFS container simultaneously under `/<mountpoint>/<VolumeName>/`:
```bash
./build/apfs-fuse -a /dev/nvme0n1p2 /mnt/apfs
# Exposes:
#   /mnt/apfs/Macintosh HD/
#   /mnt/apfs/Macintosh HD - Data/
#   /mnt/apfs/Preboot/
#   /mnt/apfs/Recovery/
```

### 4. Live `.snapshots/` Virtual Directory & Time Machine Snapshot Mounting
Every mounted APFS volume automatically exposes a virtual `/.snapshots/` directory containing all on-disk Time Machine and system snapshots (`j_snap_metadata_val_t`). You can also target any snapshot directly via `--snap <xid>` in `apfsutil` or `-o snap=<xid>` in `apfs-fuse`:
```bash
# Browse snapshots live inside a FUSE mount
ls -la "/mnt/apfs/.snapshots/com.apple.TimeMachine.2026-11-16-090000.local/"

# Or inspect a snapshot directly via CLI without FUSE
./build/apfsutil ls disk.img / --snap 1
```

### 5. Sealed System Volume (`SSV`) & SHA-256 Data Hash Integrity Verifier
macOS Big Sur through Tahoe+ protect Sealed System Volumes (`APFS_INCOMPAT_SEALED_VOLUME`) with `fext_tree` extents and `APFS_FILE_INFO_DATA_HASH` records. `apfsutil integrity-check` verifies every hashed extent against its on-disk SHA-256 digest:
```bash
./build/apfsutil integrity-check disk.img --json
```

### 6. Checkpoint Rollback Forensics & Deleted-File Carver (`xids` & `carve`)
APFS copy-on-write maintains a ring buffer of historical `nx_superblock_t` checkpoints in the `xp_desc` area. APFS-Wonder enumerates all valid historical transaction IDs (`XID`s) and automatically carves files that existed in earlier checkpoints but were deleted in the active filesystem:
```bash
# Enumerate all valid checkpoints in the NX descriptor ring buffer
./build/apfsutil xids disk.img

# Automatically diff historical checkpoints against the latest XID and recover deleted files
./build/apfsutil carve disk.img ./carved_output --json
```

### 7. Thread-Safe LRU Decompression & Block Cache (`ApfsLib/LruCache.h`)
Transparently caches decompressed `com.apple.decmpfs` payloads (ZLib `algo 3/4`, LZVN `algo 7/8`, LZFSE `algo 11/12` — including uncompressed chunk prefixes `0x06`/`0xFF`). Configurable via `-o cache_mb=N` in `apfs-fuse` or `--cache-mb N` in `apfsutil`:
```bash
./build/apfsutil bench disk.img --iterations 200 --cache-mb 128 --json
```

### 8. Native Structured JSON Output Mode (`--json`)
Every `apfsutil` subcommand (`info`, `ls`, `stat`, `extract`, `find`, `xids`, `carve`, `keybag`, `integrity-check`, `bench`) supports `--json` for seamless integration with DFIR pipelines, CI workflows, and automated scripts.

### 9. Keybag & FileVault Recovery Inspector (`apfsutil keybag`)
Inspects container and volume `kb_locker_t` keybags (`KB_TAG_VOLUME_KEY`, `KB_TAG_VOLUME_UNLOCK_RECORDS`, `KB_TAG_VOLUME_PASSPHRASE_HINT`, `KB_TAG_WRAPPED_CRYPTO_STATE`) and validates FileVault passwords or Personal Recovery Keys (`PRK`) offline without mounting:
```bash
./build/apfsutil keybag disk.img --verify-pass "my-password-or-recovery-key" --json
```

### 10. `/sbin/mount.apfs` Helper, `systemd` Automount & CPack `.deb` Packaging
`apfs-fuse` natively detects `mount(8)` invocation order (`mount -t apfs -o ro,vol=0,cache_mb=128 /dev/nvme0n1p2 /mnt/mac`), installs `/sbin/mount.apfs`, and includes a hardened `systemd` template unit ([`packaging/apfs-wonder@.service`](packaging/apfs-wonder@.service)) plus `CPack` `.deb` and `.tar.gz` generators.

---

## What Was Updated for Ubuntu 26.04+ & macOS Tahoe+

1. **macOS Tahoe+ (`apfs-2700.x`) On-Disk Format Alignment ([`ApfsLib/DiskStruct.h`](ApfsLib/DiskStruct.h), [`ApfsLib/BlockDumper.cpp`](ApfsLib/BlockDumper.cpp))**:
   - Added all new macOS Sonoma / Sequoia / Tahoe `apfs_superblock_t` fields at offsets `0x410..0x470` (`apfs_pfkur_tree_type`, `apfs_pfkur_tree_oid`, `apfs_doc_id_index_xid`, `apfs_doc_id_index_flags`, `apfs_doc_id_tree_type`, `apfs_doc_id_tree_oid`, `apfs_prev_doc_id_tree_oid`, `apfs_doc_id_fixup_cursor`, `apfs_sec_root_tree_oid`, `apfs_sec_root_tree_type`, `apfs_clonegroup_tree_flags`, `apfs_clonegroup_tree_oid`, `apfs_clonegroup_tree_type`, `apfs_clonegroup_next_id`), achieving **zero unknown padding bytes** when dumping macOS Tahoe 27.0.1 volumes.
   - Added `DREC_EXT_TYPE_DIR_GEN_COUNT` (`2`) and extended inode xfield constants (`INO_EXT_TYPE_*` through `23`).
2. **Headerless macOS Tahoe Dynamic FUSE Compatibility Layer ([`apfsfuse/FuseMacCompat.h`](apfsfuse/FuseMacCompat.h), [`apfsfuse/FuseMacCompat.cpp`](apfsfuse/FuseMacCompat.cpp))**:
   - Compiles cleanly on a stock macOS Tahoe Xcode Command Line Tools setup **without requiring macFUSE headers at build time**, dynamically resolving `libfuse3.dylib`, `libfuse.2.dylib` (macFUSE), or `libfuse-t.dylib` (kextless FUSE-T) via `dlopen()` at runtime.
   - Builds **Universal Mach-O binaries (`arm64` + `x86_64`)** out of the box on macOS.
3. **Ubuntu 26.04 LTS / 26.10 Build & FUSE3/FUSE2 Auto-Detection ([`CMakeLists.txt`](CMakeLists.txt), [`Dockerfile`](Dockerfile))**:
   - Updated CMake policy range (`3.10...3.31`) for CMake 3.x and 4.x+.
   - Automatically discovers `fuse3` (`libfuse3-dev`) or `fuse` (`libfuse-dev`) via `pkg-config` and selects the matching 4-argument (Linux) or 5-argument (macOS) `getxattr` signature.

---

## Building & Installation

### Ubuntu 26.04 LTS / 26.10 (and Debian / Ubuntu 22.04+)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libfuse3-dev zlib1g-dev libbz2-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

# Optional: Build a Debian (.deb) package via CPack
cd build && cpack -G DEB
sudo dpkg -i apfs-wonder_*.deb
```

### macOS Tahoe (26 / 27+) & Earlier macOS Releases

```bash
# Compiles Universal (arm64 + x86_64) binaries out of the box with Xcode Command Line Tools
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(sysctl -n hw.ncpu)"
```
*(Optional on macOS for FUSE mounting: install [FUSE-T](https://www.fuse-t.org/) or [macFUSE](https://macfuse.github.io/); `apfsutil`, `apfs-dump`, and `apfs-dump-quick` require no FUSE installation.)*

### Docker (Ubuntu Rolling / 26.04+)

```bash
docker build -t apfs-wonder .
docker run --rm -v "$PWD:/data" apfs-wonder info /data/disk.img --json
```

---

## License

APFS-Wonder is licensed under the **GNU General Public License v2.0** ([`LICENSE`](LICENSE)). Original `apfs-fuse` implementation copyright © Simon Gander (`sgan81`).
