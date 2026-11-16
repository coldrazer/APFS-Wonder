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

[**The Evolution**](#-the-evolution-from-legacy-apfs-fuse-to-apfs-wonder) •
[**10 Production Add-Ons**](#-deep-dive-the-10-production-add-ons) •
[**Evaluation & Benchmarks**](#-evaluation--benchmark-results) •
[**Build & Install**](#-building--installation)

</div>

---

## Overview

**APFS-Wonder** is a ground-up modernization and feature expansion of [`sgan81/apfs-fuse`](https://github.com/sgan81/apfs-fuse), purpose-built for **latest Ubuntu (26.04 LTS / 26.10)** and **latest macOS Tahoe+ (macOS 26 / 27+, `apfs-2700.x`)**.

While the original `sgan81/apfs-fuse` pioneered open-source read-only APFS access for early macOS High Sierra / Mojave volumes, modern Apple File System containers (Catalina through macOS Tahoe+) introduced **System/Data Volume Groups**, **Firmlinks (`APFS_SF_FIRMLINK`)**, ** Cryptographically Sealed System Volumes (`SSV`)**, **expanded `apfs_superblock_t` trees (`pfkur`, `doc_id`, `sec_root`, `clonegroup`)**, and **modern FUSE3 / kextless macOS FUSE runtimes** that broke legacy builds and workflows.

**APFS-Wonder** bridges that 7-year gap—bringing zero-warning **Clang 21+** and **GCC 16+** builds, **CMake 3.10–4.x+** support, **Universal (`arm64` + `x86_64`)** macOS binaries, and **10 production-ready add-ons** for developers, sysadmins, and digital forensics & incident response (DFIR) engineers.

---

## 🧬 The Evolution: From Legacy `apfs-fuse` to `APFS-Wonder`

```mermaid
flowchart LR
    subgraph Legacy["Legacy sgan81/apfs-fuse (2017–2020)"]
        L1["CMake 3.0.2 (Breaks on CMake 4.x)"]
        L2["Hardcoded OSXFUSE / FUSE 2.x"]
        L3["Mojave/Catalina Superblock (Bytes 0x410+ Unknown)"]
        L4["Single-Volume FUSE Mount Only"]
        L5["Broken Firmlinks (/Users Empty on System Vol)"]
        L6["Uncached Decompression (Re-decodes on Every Read)"]
    end

    subgraph Wonder["APFS-Wonder (2026 Modern Architecture)"]
        W1["CMake 3.10..3.31 + C++17 (Clang 21 & GCC 16, 0 Warnings)"]
        W2["Ubuntu 26.04+ FUSE3/FUSE2 + macOS Tahoe Runtime dlopen()"]
        W3["Full macOS Tahoe+ v27 Superblock & Extended Inode xfields"]
        W4["10 Production Add-Ons: Rootless CLI, SSV, Carver, LRU Cache, JSON"]
        W5["Automatic System + Data Volume Group Firmlink Stitching"]
        W6["17.9 GiB/s Thread-Safe LRU Decompression Cache (4.6x Speedup)"]
    end

    Legacy ==>|"7-Year Architectural Leap"| Wonder
```

### Side-by-Side Evolution Matrix

| Capability / Layer | Original `sgan81/apfs-fuse` | Modern `APFS-Wonder` |
| :--- | :--- | :--- |
| **Target Operating Systems** | Ubuntu 18.04–20.04, macOS 10.12–10.15 | **Ubuntu 26.04 LTS / 26.10**, **macOS Tahoe (26 / 27+)**, Debian 12/13+ |
| **Build System & Compilers** | `cmake_minimum_required(VERSION 3.0.2)` (**fails on CMake 4.x**); C++11/C11 with dozens of modern compiler warnings | `cmake_minimum_required(VERSION 3.10...3.31)`; **C++17** with **0 warnings / 0 errors** on **Apple Clang 21.0** & **GNU GCC 16.2** |
| **macOS FUSE Architecture** | Hard-coded `/usr/local/include/osxfuse`; fails to compile if macFUSE isn't pre-installed; `x86_64` only | **Headerless `FuseMacCompat` runtime loader (`dlopen`)** supporting **macFUSE (`libfuse3`/`libfuse.2`)** & **kextless FUSE-T (`libfuse-t`)**; **Universal `arm64 + x86_64` binaries** |
| **Linux FUSE Architecture** | Static `fuse` lookup; manual `getxattr` `#ifdef` edits required | Automated `pkg-config` discovery for **`fuse3`** (`libfuse3-dev`) and **`fuse`** (`libfuse-dev`) with dual 4-arg/5-arg `getxattr` overloads |
| **APFS On-Disk Specification** | Stops at early `apfs_superblock_t` offset `0x410`; reports `unknown` bytes on Sonoma/Sequoia/Tahoe | Full **macOS Tahoe+ (`apfs-2700.x`)** struct coverage through `0x470` (`pfkur_tree`, `doc_id_tree`, `sec_root_tree`, `clonegroup_tree`) + `INO_EXT_TYPE_*` up to `23` (**0 unknown bytes**) |
| **Rootless Access (No FUSE)** | Not supported (`apfsutil` only listed volume names) | **Add-On #1**: Full rootless CLI (`ls`, `tree`, `stat`, `cat`, `extract`, `find`) — zero root or kernel FUSE needed |
| **macOS Volume Groups** | Mounting `System` volume leaves `/Users`, `/Applications`, `/Library` as broken empty stubs | **Add-On #2**: Automatic `System` (`0x0001`) + `Data` (`0x0040`) Volume Group pairing & transparent `com.apple.fs.firmlink` traversal |
| **Multi-Volume Containers** | Mounts only 1 volume index (`-v N`) per process | **Add-On #3**: Whole-container auto-mounter (`-a` / `-o all_vols`) exposing `/<mountpoint>/<VolumeName>/` for every volume |
| **Time Machine Snapshots** | Hidden unless manually looked up by XID and remounted | **Add-On #4**: Live `/.snapshots/<snap_name>/` virtual directory inside every mounted volume + `--snap <xid>` CLI support |
| **Sealed System Volumes (`SSV`)** | Crashes or fails extent assertions on sealed inodes; ignores SHA-256 hashes | **Add-On #5**: Full `fext_tree` support + `apfsutil integrity-check` cryptographic SHA-256 verifier for `APFS_FILE_INFO_DATA_HASH` |
| **Forensics & Deleted Files** | Only mounts active superblock; no checkpoint enumeration or carving | **Add-On #6**: `apfsutil xids` ring-buffer scanner + `apfsutil carve` historical checkpoint differ & deleted-file recovery engine |
| **Decompression Performance** | Re-reads and re-decompresses `com.apple.decmpfs` on every 4 KB/64 KB read call | **Add-On #7**: Thread-safe byte-bounded **LRU Decompression Cache** (`LruCache.h`) delivering **17,960 MiB/s** warm throughput (**4.6× speedup**) |
| **Automation & Output Format** | Unstructured plain-text `stdout` with debug noise (`st_mode = ...`) | **Add-On #8**: Clean `stdout` + native structured `--json` mode across all `apfsutil` commands |
| **Encryption & Keybags** | Interactive password prompt only; no keybag inspection CLI | **Add-On #9**: `apfsutil keybag` inspector (`KB_TAG_*` enumeration) + non-interactive `--verify-pass` FileVault / PRK validator |
| **OS Integration & Packaging** | Manual binary copy; incompatible with `/etc/fstab` `mount(8)` | **Add-On #10**: `/sbin/mount.apfs` helper (`mount -t apfs`), `systemd` template unit (`apfs-wonder@.service`), `Dockerfile`, and CPack `.deb`/`TGZ` packages |

---

## 🚀 Deep Dive: The 10 Production Add-Ons

### Add-On #1: Rootless / FUSE-less CLI Extractor & Browser (`apfsutil`)
* **What It Does**: Transforms `apfsutil` from a 100-line volume-listing stub into a complete, dependency-free userspace APFS browser and file extractor supporting `info`, `ls`, `tree`, `stat`, `cat`, `extract`, and `find`.
* **Why It Matters**: In cloud CI runners, Docker containers, locked-down forensic workstations, or macOS systems without kernel extensions enabled, loading a FUSE kernel module or running as `root` is often impossible. Add-On #1 lets any unprivileged user browse and extract entire APFS containers directly from raw images, DMGs, or block devices.
* **How It Works**: Uses `ApfsDir::ResolvePath()` and `ApfsDir::ReadFileSmart()` ([`ApfsLib/ApfsDir.cpp`](ApfsLib/ApfsDir.cpp)) to traverse the volume's `m_fs_tree` B-tree, transparently decoding inline and resource-fork `com.apple.decmpfs` streams (ZLib, LZVN, LZFSE), standard data streams (`j_phys_ext_val_t`), and sealed volume extents (`fext_tree`).
* **Usage**:
  ```bash
  ./build/apfsutil info disk.img
  ./build/apfsutil ls disk.img /
  ./build/apfsutil tree disk.img / --depth 3
  ./build/apfsutil stat disk.img /readme.txt
  ./build/apfsutil cat disk.img /readme.txt
  ./build/apfsutil extract disk.img / ./extracted_root
  ./build/apfsutil find disk.img secret
  ```

---

### Add-On #2: Transparent Volume Group & Firmlink Stitching (`System` + `Data`)
* **What It Does**: Automatically pairs a macOS `System` volume (`APFS_VOL_ROLE_SYSTEM = 0x0001`) with its companion `Data` volume (`APFS_VOL_ROLE_DATA = 0x0040`) sharing the same `apfs_volume_group_id` UUID, transparently resolving `APFS_SF_FIRMLINK` (`0x00800000`) directory portals across volumes.
* **Why It Matters**: Since macOS Catalina (and mandatory in Big Sur through macOS Tahoe+), Apple splits the root filesystem across two separate APFS volumes. In legacy `apfs-fuse`, mounting volume `0` (`System`) leaves `/Users`, `/Library`, `/Applications`, and `/private/var` as dead stubs because their contents live on the `Data` volume.
* **How It Works**: `ApfsContainer::FindVolumeByRole()` ([`ApfsLib/ApfsContainer.cpp`](ApfsLib/ApfsContainer.cpp)) locates the companion `Data` volume by matching `apfs_volume_group_id`. Whenever `ApfsFuse` ([`apfsfuse/ApfsFuse.cpp`](apfsfuse/ApfsFuse.cpp)) or `ApfsDir::ResolvePath()` encounters an inode with `bsd_flags & APFS_SF_FIRMLINK` and the `com.apple.fs.firmlink` xattr, it seamlessly switches the lookup context to the target path on the paired `Data` volume.
* **Usage**:
  ```bash
  # Automatically follows /Users firmlink from System Volume (vol 0) into Data Volume (vol 1)
  ./build/apfsutil cat disk.img /Users/profile.txt
  ```

---

### Add-On #3: Multi-Volume / Whole-Container Auto-Mounter (`apfs-fuse -a` / `-o all_vols`)
* **What It Does**: Mounts **all** volumes inside an APFS container (`System`, `Data`, `Preboot`, `Recovery`, `VM`, or custom volumes) simultaneously under a single mountpoint as `/<mountpoint>/<VolumeName>/`.
* **Why It Matters**: Modern macOS containers routinely hold 5–7 APFS volumes. Previously, inspecting all volumes required spawning 5–7 separate `apfs-fuse` processes on different mountpoints.
* **How It Works**: Multi-slot virtual root routing in [`apfsfuse/ApfsFuse.cpp`](apfsfuse/ApfsFuse.cpp) encodes the volume slot index into the upper bits of the 64-bit FUSE inode number (`(slot << 48) | ino`), synthesizing top-level directory entries for each volume name and dispatching FUSE operations (`getattr`, `readdir`, `read`, `readlink`, `getxattr`) to the owning `ApfsVolume` instance.
* **Usage**:
  ```bash
  ./build/apfs-fuse -a /dev/nvme0n1p2 /mnt/apfs
  # Or via FUSE -o option:
  ./build/apfs-fuse -o all_vols /dev/nvme0n1p2 /mnt/apfs
  ```

---

### Add-On #4: Live `.snapshots/` Virtual Directory & Time Machine Snapshot Mounting
* **What It Does**: Exposes a live virtual `/.snapshots/<snapshot_name>/` directory at the root of every mounted APFS volume in `apfs-fuse`, and adds `--snap <xid>` across all `apfsutil` subcommands.
* **Why It Matters**: APFS Time Machine local snapshots (`com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.local`) and OS update snapshots preserve point-in-time states of the entire volume. Users can now `cd /.snapshots/` inside any mounted volume to compare or copy historical files side-by-side with the live filesystem.
* **How It Works**: `ApfsVolume::ListSnapshots()` ([`ApfsLib/ApfsVolume.cpp`](ApfsLib/ApfsVolume.cpp)) iterates `m_snap_meta_tree` (`APFS_TYPE_SNAP_METADATA`), extracting each snapshot's `xid`, `sblock_oid`, creation/change timestamps, and UTF-8 name. Accessing `/.snapshots/<name>` lazily initializes a snapshot-pinned `ApfsVolume` instance via `MountSnapshot()`.
* **Usage**:
  ```bash
  # CLI snapshot browsing without FUSE
  ./build/apfsutil ls disk.img / --snap 1
  # Or inside a mounted FUSE filesystem
  ls -la /mnt/apfs/.snapshots/
  ```

---

### Add-On #5: Sealed System Volume (`SSV`) & SHA-256 Data Hash Integrity Verifier
* **What It Does**: Adds complete support for macOS Sealed System Volumes (`APFS_INCOMPAT_SEALED_VOLUME = 0x00000100`) and provides `apfsutil integrity-check` to cryptographically verify file extents against on-disk `APFS_FILE_INFO_DATA_HASH` SHA-256 digests.
* **Why It Matters**: Starting in macOS Big Sur through Tahoe+, the `System` volume stores file extents in `fext_tree` and protects file blocks with SHA-256 hashes (`j_file_info_key_t` / `j_file_info_val_t`). Legacy tools either failed assertions on `fext_key->private_id` or silently ignored data corruption.
* **How It Works**: `ApfsDir::ListFileDataHashes()` and `ApfsDir::VerifyFileIntegrity()` ([`ApfsLib/ApfsDir.cpp`](ApfsLib/ApfsDir.cpp)) scan `APFS_TYPE_FILE_INFO` (`13`) records for each file inode, extract `APFS_FILE_INFO_DATA_HASH` (`j_file_info_data_hash_val_t`), read the corresponding logical block range (`lba`, `hashed_len * block_size`), compute the SHA-256 digest via `SHA256`, and verify bit-for-bit equality against the stored hash.
* **Usage**:
  ```bash
  ./build/apfsutil integrity-check disk.img --json
  ```

---

### Add-On #6: Checkpoint Rollback Forensics & Deleted-File Carver (`xids` & `carve`)
* **What It Does**: Scans the APFS container's checkpoint descriptor ring buffer (`nx_xp_desc_base .. nx_xp_desc_base + nx_xp_desc_blocks`) to list all historical transaction checkpoints (`apfsutil xids`) and automatically recovers deleted files from older checkpoints (`apfsutil carve`).
* **Why It Matters**: Because APFS is copy-on-write (CoW), deleting a file does not immediately overwrite its inode, directory record (`drec`), or physical extents—older `nx_superblock_t` checkpoints in the descriptor ring still point to earlier versions of the volume OMap and FSTree.
* **How It Works**: `ApfsContainer::ListCheckpoints()` ([`ApfsLib/ApfsContainer.cpp`](ApfsLib/ApfsContainer.cpp)) validates every `OBJECT_TYPE_NX_SUPERBLOCK` block in the descriptor ring with Fletcher-64 (`VerifyBlock`). `apfsutil carve` ([`ApfsUtil/ApfsUtil.cpp`](ApfsUtil/ApfsUtil.cpp)) inventories all file paths in the active checkpoint (`max_xid`), then walks historical checkpoints and snapshots to locate and extract files that were subsequently unlinked.
* **Usage**:
  ```bash
  # List all valid historical checkpoints in the NX ring buffer
  ./build/apfsutil xids disk.img

  # Diff historical checkpoints/snapshots and recover deleted files
  ./build/apfsutil carve disk.img ./recovered_forensics --json
  ```

---

### Add-On #7: Thread-Safe LRU Block & Decompression Cache (`ApfsLib/LruCache.h`)
* **What It Does**: Introduces a thread-safe, byte-bounded Least-Recently-Used (LRU) decompression cache (`ApfsDecompCache`) for `com.apple.decmpfs` compressed files (ZLib, LZVN, LZFSE) and a built-in microbenchmark command (`apfsutil bench`).
* **Why It Matters**: macOS heavily compresses system binaries, libraries, and assets using `com.apple.decmpfs`. Without caching, every sequential 4 KB or 64 KB FUSE read request re-reads and re-decompresses the entire compressed resource fork or inline payload from scratch, causing massive CPU amplification.
* **How It Works**: [`ApfsLib/LruCache.h`](ApfsLib/LruCache.h) implements an `O(1)` lookup/eviction cache keyed by `(volume_ptr, ino)` protected by `std::mutex`, bounded by configurable megabytes (`-o cache_mb=N` in `apfs-fuse`, `--cache-mb N` in `apfsutil`, default 128 MiB), with atomic hit/miss/eviction counters. Also fixes uncompressed-chunk prefix handling (`0x06`/`0xFF`) for LZFSE (`algo 11/12`) in [`ApfsLib/Decmpfs.cpp`](ApfsLib/Decmpfs.cpp).
* **Usage**:
  ```bash
  # Run cold vs. warm decompression benchmark
  ./build/apfsutil bench disk.img --iterations 200 --cache-mb 128 --json

  # Mount with a 256 MiB LRU cache
  ./build/apfs-fuse -o cache_mb=256 disk.img /mnt/apfs
  ```

---

### Add-On #8: Native Structured JSON Output Mode (`--json`)
* **What It Does**: Adds `--json` to every `apfsutil` subcommand (`info`, `ls`, `stat`, `extract`, `find`, `xids`, `carve`, `keybag`, `integrity-check`, `bench`) and silences legacy debug chatter on `stdout`.
* **Why It Matters**: Security automation, DFIR orchestrators, and CI test suites need deterministic, machine-parseable output without fragile regex scraping.
* **How It Works**: Dedicated JSON serializers in [`ApfsUtil/ApfsUtil.cpp`](ApfsUtil/ApfsUtil.cpp) emit RFC 8259-compliant JSON objects with escaped strings, UUID formatting, role decoding, and latency/cache telemetry.
* **Usage**:
  ```bash
  ./build/apfsutil info disk.img --json | jq .
  ```

---

### Add-On #9: Keybag & FileVault Recovery Inspector (`apfsutil keybag`)
* **What It Does**: Parses and displays container and volume `kb_locker_t` keybags (`KB_TAG_VOLUME_KEY`, `KB_TAG_VOLUME_UNLOCK_RECORDS`, `KB_TAG_VOLUME_PASSPHRASE_HINT`, `KB_TAG_WRAPPED_CRYPTO_STATE`, `KB_TAG_VOLUME_MUSER_LOCKER`) and validates FileVault passwords or Personal Recovery Keys (`PRK`) via `--verify-pass <passphrase>`.
* **Why It Matters**: Auditing FileVault keybags, retrieving password hints, or verifying whether a user password / recovery key unlocks a volume previously required interactive mounting.
* **How It Works**: `KeyManager::GetKeybagInfo()` ([`ApfsLib/KeyMgmt.cpp`](ApfsLib/KeyMgmt.cpp)) decrypts the container keylocker (`nx_keylocker`) using the container UUID as the AES-XTS key, walks each `keybag_entry_t`, follows `prange_t` pointers to per-volume keybags, and tests PBKDF2-HMAC-SHA256 + RFC 3394 AES Key Unwrap against the Volume Encryption Key (`VEK`).
* **Usage**:
  ```bash
  ./build/apfsutil keybag disk.img --verify-pass "MyFileVaultPassphrase" --json
  ```

---

### Add-On #10: `/sbin/mount.apfs` Helper, `systemd` Automount & CPack `.deb` Packaging
* **What It Does**: Enables standard Linux `mount -t apfs /dev/sdX /mnt/apfs` and `/etc/fstab` integration, ships a hardened `systemd` template service ([`packaging/apfs-wonder@.service`](packaging/apfs-wonder@.service)), a multi-stage Ubuntu [`Dockerfile`](Dockerfile), and `CPack` `.deb`/`TGZ` package generation.
* **Why It Matters**: Linux `mount(8)` invokes `/sbin/mount.<fstype> <device> <mountpoint> [-o <options>]` with positional arguments before `-o`, whereas original `apfs-fuse` only accepted options before positional arguments (`getopt`).
* **How It Works**: Custom argument normalization in [`apfsfuse/ApfsFuse.cpp`](apfsfuse/ApfsFuse.cpp) accepts `-o` options both before and after `<device> <mountpoint>`, strips standard `mount(8)` flags (`rw`, `noauto`, `user`, `nofail`), parses custom options (`vol=N`, `all_vols`, `snap=XID`, `cache_mb=N`, `pass=...`, `lax`), and installs `/sbin/mount.apfs` via CMake/CPack.
* **Usage**:
  ```bash
  # Standard Linux mount(8) syntax
  sudo mount -t apfs -o ro,all_vols,cache_mb=256 /dev/nvme0n1p2 /mnt/apfs

  # systemd template unit
  sudo systemctl start apfs-wonder@nvme0n1p2.service
  ```

---

## 📊 Evaluation & Benchmark Results

All 10 production add-ons are verified end-to-end by [`tests/run_evals.py`](tests/run_evals.py) against both **native macOS Tahoe 27.0.1 APFS containers** (`/sbin/newfs_apfs`) and synthetic multi-volume/multi-checkpoint forensic images.

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

To run the evaluation suite yourself:

```bash
python3 tests/run_evals.py
```

---

## 🛠️ Building & Installation

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
