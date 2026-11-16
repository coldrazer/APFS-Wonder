/*
	This file is part of apfs-fuse, a read-only implementation of APFS
	(Apple File System) for FUSE.
	Copyright (C) 2017 Simon Gander

	Apfs-fuse is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	Apfs-fuse is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with apfs-fuse.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef USE_FUSE2
#define FUSE_USE_VERSION 26
#else
#define FUSE_USE_VERSION 30
#endif

#ifdef __linux__
#ifdef USE_FUSE2
#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>
#else
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#endif
#include <unistd.h>
#endif
#ifdef __APPLE__
#if defined(APFS_FUSE_DYNAMIC_MACOS)
#include "FuseMacCompat.h"
#elif defined(USE_FUSE2)
#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>
#else
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#endif
#include <unistd.h>
#endif

#include <fcntl.h>
#include <getopt.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/Decmpfs.h>
#include <ApfsLib/DeviceLinux.h>
#include <ApfsLib/DeviceMac.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/LruCache.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstddef>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

static_assert(sizeof(fuse_ino_t) == 8, "Sorry, on 32-bit systems, you need to use FUSE-3.");

constexpr double FUSE_TIMEOUT = 86400.0;
constexpr uint64_t INO_RAW_MASK = 0x0000FFFFFFFFFFFFULL;
constexpr uint64_t INO_SLOT_SHIFT = 48;
constexpr uint64_t INO_SLOT_MASK = 0xFFULL;
constexpr uint64_t INO_VIRTUAL_SNAP_DIR_BIT = (1ULL << 56);
constexpr uint64_t INO_VIRTUAL_CONTAINER_ROOT = 1ULL;

static inline fuse_ino_t make_ino(uint8_t slot, uint64_t raw_ino, bool is_snap_dir = false)
{
	return (is_snap_dir ? INO_VIRTUAL_SNAP_DIR_BIT : 0ULL) |
	       (static_cast<uint64_t>(slot) << INO_SLOT_SHIFT) |
	       (raw_ino & INO_RAW_MASK);
}

static inline uint8_t get_ino_slot(fuse_ino_t ino)
{
	return static_cast<uint8_t>((ino >> INO_SLOT_SHIFT) & INO_SLOT_MASK);
}

static inline uint64_t get_raw_ino(fuse_ino_t ino)
{
	return ino & INO_RAW_MASK;
}

static inline bool is_virtual_snap_dir(fuse_ino_t ino)
{
	return (ino & INO_VIRTUAL_SNAP_DIR_BIT) != 0;
}

struct VolumeSlot
{
	unsigned int fsid = 0;
	xid_t snap_xid = 0;
	std::string label;
	std::unique_ptr<ApfsVolume> vol;
};

static struct fuse_lowlevel_ops ops;
static Device *g_disk_main = nullptr;
static Device *g_disk_tier2 = nullptr;
static ApfsContainer *g_container = nullptr;
static ApfsVolume *g_volume = nullptr;
static std::vector<VolumeSlot> g_slots;
static std::mutex g_slots_mutex;
static int g_companion_data_slot = -1;
static unsigned int g_vol_id = 0;
static uid_t g_uid = 0;
static gid_t g_gid = 0;
static xid_t g_xid = 0;
static bool g_set_uid = false;
static bool g_set_gid = false;
static int g_physblksize = 512;
static std::string g_password;
static xid_t g_snap_xid = 0;
static bool g_all_volumes = false;
static bool g_resolve_firmlinks = true;
static size_t g_cache_mb = 128;

static ApfsVolume *get_slot_volume(uint8_t slot)
{
	std::lock_guard<std::mutex> lock(g_slots_mutex);
	if (slot < g_slots.size() && g_slots[slot].vol)
		return g_slots[slot].vol.get();
	return g_volume;
}

static int get_or_mount_snapshot_slot(unsigned int fsid, xid_t snap_xid, const std::string &snap_name)
{
	std::lock_guard<std::mutex> lock(g_slots_mutex);
	for (size_t i = 0; i < g_slots.size(); ++i)
	{
		if (g_slots[i].fsid == fsid && g_slots[i].snap_xid == snap_xid && g_slots[i].vol)
			return static_cast<int>(i);
	}
	if (g_slots.size() >= 250)
		return -1;

	std::unique_ptr<ApfsVolume> sv(g_container->GetVolume(fsid, g_password, snap_xid));
	if (!sv)
		return -1;

	VolumeSlot vs;
	vs.fsid = fsid;
	vs.snap_xid = snap_xid;
	vs.label = snap_name;
	vs.vol = std::move(sv);
	g_slots.push_back(std::move(vs));
	return static_cast<int>(g_slots.size() - 1);
}

struct Directory
{
	Directory() {}
	~Directory() {}

	std::vector<char> dirbuf;
};

struct File
{
	File() : vol(nullptr) {}
	~File() {}

	bool IsCompressed() const { return (ino.bsd_flags & APFS_UF_COMPRESSED) != 0; }

	ApfsVolume *vol;
	ApfsDir::Inode ino;
	std::vector<uint8_t> decomp_data;
};

static bool apfs_stat_internal(fuse_ino_t ino, struct stat &st)
{
	memset(&st, 0, sizeof(st));

	if (g_all_volumes && ino == INO_VIRTUAL_CONTAINER_ROOT)
	{
		st.st_ino = INO_VIRTUAL_CONTAINER_ROOT;
		st.st_mode = S_IFDIR | 0755;
		st.st_nlink = 2;
		st.st_uid = g_uid;
		st.st_gid = g_gid;
		return true;
	}

	if (is_virtual_snap_dir(ino))
	{
		st.st_ino = ino;
		st.st_mode = S_IFDIR | 0555;
		st.st_nlink = 2;
		st.st_uid = g_uid;
		st.st_gid = g_gid;
		return true;
	}

	uint8_t slot = get_ino_slot(ino);
	uint64_t raw_ino = get_raw_ino(ino);
	ApfsVolume *vol = get_slot_volume(slot);
	if (!vol)
		return false;

	ApfsDir dir(*vol);
	ApfsDir::Inode rec;
	bool rc = false;

	if (raw_ino == ROOT_DIR_PARENT)
	{
		st.st_ino = ino;
		st.st_mode = S_IFDIR | 0755;
		st.st_nlink = 2;
		st.st_uid = g_uid;
		st.st_gid = g_gid;
		return true;
	}

	rc = dir.GetInode(rec, raw_ino);

	if (!rc)
	{
		std::cerr << "Unable to read inode " << raw_ino << std::endl;
		return false;
	}
	else
	{
		constexpr uint64_t div_nsec = 1000000000;

		st.st_ino = ino;
		st.st_mode = rec.mode;
		st.st_nlink = 1;

		st.st_uid = g_set_uid ? g_uid : rec.owner;
		st.st_gid = g_set_gid ? g_gid : rec.group;

		if (rec.optional_present_flags & ApfsDir::Inode::INO_HAS_RDEV)
			st.st_rdev = rec.rdev;

		if (S_ISREG(st.st_mode))
		{
			if (rec.bsd_flags & APFS_UF_COMPRESSED) // Compressed
			{
				if (rec.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE) {
					st.st_size = rec.uncompressed_size;
				} else {
					std::vector<uint8_t> data;
					rc = dir.GetAttribute(data, raw_ino, "com.apple.decmpfs");
					if (rc)
					{
						const CompressionHeader *decmpfs = reinterpret_cast<const CompressionHeader *>(data.data());

						if (IsDecompAlgoSupported(decmpfs->algo))
						{
							st.st_size = decmpfs->size;
							if (g_debug & Dbg_Cmpfs)
								std::cout << "Compressed size " << decmpfs->size << " bytes." << std::endl;
						}
						else if (IsDecompAlgoInRsrc(decmpfs->algo))
						{
							rc = dir.GetAttribute(data, raw_ino, "com.apple.ResourceFork");

							if (!rc)
								st.st_size = 0;
							else
								st.st_size = data.size();
						}
						else
						{
							st.st_size = data.size();
							std::cerr << "Unknown compression algorithm " << decmpfs->algo << std::endl;
							if (!g_lax)
								return false;
						}
					}
					else
					{
						std::cerr << "Flag 0x20 set but no com.apple.decmpfs attribute!!!" << std::endl;
						if (!g_lax)
							return false;
					}
				}
			}
			else if (rec.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM)
			{
				st.st_size = rec.ds_size;
			}
			else
			{
				st.st_size = 0;
			}
		}
		else if (S_ISDIR(st.st_mode))
		{
			st.st_size = rec.nchildren_nlink;
		}

#ifdef __linux__
		st.st_mtim.tv_sec = rec.mod_time / div_nsec;
		st.st_mtim.tv_nsec = rec.mod_time % div_nsec;
		st.st_ctim.tv_sec = rec.change_time / div_nsec;
		st.st_ctim.tv_nsec = rec.change_time % div_nsec;
		st.st_atim.tv_sec = rec.access_time / div_nsec;
		st.st_atim.tv_nsec = rec.access_time % div_nsec;
#endif
#ifdef __APPLE__
		st.st_birthtimespec.tv_sec = rec.create_time / div_nsec;
		st.st_birthtimespec.tv_nsec = rec.create_time % div_nsec;
		st.st_mtimespec.tv_sec = rec.mod_time / div_nsec;
		st.st_mtimespec.tv_nsec = rec.mod_time % div_nsec;
		st.st_ctimespec.tv_sec = rec.change_time / div_nsec;
		st.st_ctimespec.tv_nsec = rec.change_time % div_nsec;
		st.st_atimespec.tv_sec = rec.access_time / div_nsec;
		st.st_atimespec.tv_nsec = rec.access_time % div_nsec;
#endif
		return true;
	}
}

static void apfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void)fi;

	bool rc = false;
	struct stat st;

	if (g_debug & Dbg_Info)
		std::cout << "apfs_getattr: ino=" << ino << " => ";

	rc = apfs_stat_internal(ino, st);

	if (g_debug & Dbg_Info)
		std::cout << (rc ? "OK" : "FAIL") << std::endl;

	if (rc)
		fuse_reply_attr(req, &st, FUSE_TIMEOUT);
	else
		fuse_reply_err(req, ENOENT);
}

[[maybe_unused]] static void apfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size, uint32_t position)
{
	if ((g_all_volumes && ino == INO_VIRTUAL_CONTAINER_ROOT) || is_virtual_snap_dir(ino))
	{
#if defined(__APPLE__) && defined(ENOATTR)
		fuse_reply_err(req, ENOATTR);
#else
		fuse_reply_err(req, ENODATA);
#endif
		return;
	}

	ApfsVolume *vol = get_slot_volume(get_ino_slot(ino));
	if (!vol)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	ApfsDir dir(*vol);
	bool rc = false;
	std::vector<uint8_t> data;

	if (g_debug & Dbg_Info)
		std::cout << "apfs_getxattr: " << std::hex << ino << " " << name << " => ";

	rc = dir.GetAttribute(data, get_raw_ino(ino), name);

	if (g_debug & Dbg_Info)
		std::cout << (rc ? "OK" : "FAIL") << std::endl;

	if (!rc)
#if defined(__APPLE__) && defined(ENOATTR)
		fuse_reply_err(req, ENOATTR);
#else
		fuse_reply_err(req, ENODATA);
#endif
	else
	{
		if (size == 0)
			fuse_reply_xattr(req, data.size()); // xattr size
		else if (static_cast<size_t>(position) >= data.size())
			fuse_reply_buf(req, nullptr, 0);
		else
			fuse_reply_buf(req, reinterpret_cast<const char *>(data.data() + position), std::min(data.size() - static_cast<size_t>(position), size));
	}
}

[[maybe_unused]] static void apfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
	apfs_getxattr(req, ino, name, size, 0);
}

static void apfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	if ((g_all_volumes && ino == INO_VIRTUAL_CONTAINER_ROOT) || is_virtual_snap_dir(ino))
	{
		if (size == 0)
			fuse_reply_xattr(req, 0);
		else
			fuse_reply_buf(req, "", 0);
		return;
	}

	ApfsVolume *vol = get_slot_volume(get_ino_slot(ino));
	if (!vol)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	ApfsDir dir(*vol);
	bool rc = false;
	std::vector<std::string> names;
	std::string reply;

	rc = dir.ListAttributes(names, get_raw_ino(ino));

	if (g_debug & Dbg_Info)
		std::cout << "apfs_listxattr:" << std::endl;

	if (rc)
	{
		for (size_t k = 0; k < names.size(); k++)
		{
			if (g_debug & Dbg_Info)
				std::cout << names[k] << std::endl;
			reply.append(names[k]);
			reply.push_back(0);
		}
	}

	if (size == 0)
		fuse_reply_xattr(req, reply.size());
	else if (size < reply.size())
		fuse_reply_err(req, ERANGE);
	else
		fuse_reply_buf(req, reply.c_str(), reply.size());
}

static void apfs_lookup(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	if (g_debug & Dbg_Info)
		std::cout << "apfs_lookup: ino=" << ino << " name=" << name << " => ";

	// 1. Multi-volume container root lookup
	if (g_all_volumes && ino == INO_VIRTUAL_CONTAINER_ROOT)
	{
		std::lock_guard<std::mutex> lock(g_slots_mutex);
		for (size_t i = 0; i < g_slots.size(); ++i)
		{
			if (g_slots[i].snap_xid == 0 && g_slots[i].label == name && g_slots[i].vol)
			{
				fuse_entry_param e;
				memset(&e, 0, sizeof(e));
				e.ino = make_ino(static_cast<uint8_t>(i), ROOT_DIR_INO_NUM);
				e.attr_timeout = FUSE_TIMEOUT;
				e.entry_timeout = FUSE_TIMEOUT;
				apfs_stat_internal(e.ino, e.attr);
				fuse_reply_entry(req, &e);
				return;
			}
		}
		fuse_reply_err(req, ENOENT);
		return;
	}

	uint8_t slot = get_ino_slot(ino);
	uint64_t raw_ino = get_raw_ino(ino);
	ApfsVolume *vol = get_slot_volume(slot);
	if (!vol)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	// 2. Inside virtual .snapshots directory
	if (is_virtual_snap_dir(ino))
	{
		std::vector<ApfsSnapshotInfo> snaps;
		vol->ListSnapshots(snaps);
		for (const auto &s : snaps)
		{
			if (s.name == name)
			{
				unsigned int fsid = g_vol_id;
				{
					std::lock_guard<std::mutex> lock(g_slots_mutex);
					if (slot < g_slots.size())
						fsid = g_slots[slot].fsid;
				}
				int snap_slot = get_or_mount_snapshot_slot(fsid, s.snap_xid, s.name);
				if (snap_slot >= 0)
				{
					fuse_entry_param e;
					memset(&e, 0, sizeof(e));
					e.ino = make_ino(static_cast<uint8_t>(snap_slot), ROOT_DIR_INO_NUM);
					e.attr_timeout = FUSE_TIMEOUT;
					e.entry_timeout = FUSE_TIMEOUT;
					apfs_stat_internal(e.ino, e.attr);
					fuse_reply_entry(req, &e);
					return;
				}
			}
		}
		fuse_reply_err(req, ENOENT);
		return;
	}

	// 3. Lookup of ".snapshots" at volume root
	if ((raw_ino == ROOT_DIR_PARENT || raw_ino == ROOT_DIR_INO_NUM) && strcmp(name, ".snapshots") == 0)
	{
		fuse_entry_param e;
		memset(&e, 0, sizeof(e));
		e.ino = make_ino(slot, ROOT_DIR_INO_NUM, true);
		e.attr_timeout = FUSE_TIMEOUT;
		e.entry_timeout = FUSE_TIMEOUT;
		apfs_stat_internal(e.ino, e.attr);
		fuse_reply_entry(req, &e);
		return;
	}

	ApfsDir dir(*vol);
	ApfsDir::DirRec res;
	bool rc = dir.LookupName(res, raw_ino, name);

	if (g_debug & Dbg_Info)
		std::cout << (rc ? "OK" : "FAIL") << std::endl;

	if (!rc)
	{
		fuse_reply_err(req, ENOENT);
	}
	else
	{
		fuse_ino_t target_ino = make_ino(slot, res.file_id);

		// Transparent Firmlink resolution across System -> Data volume group
		if (g_resolve_firmlinks && g_companion_data_slot >= 0 && slot != static_cast<uint8_t>(g_companion_data_slot))
		{
			ApfsDir::Inode irec;
			if (dir.GetInode(irec, res.file_id) && (irec.bsd_flags & APFS_SF_FIRMLINK))
			{
				std::vector<uint8_t> fl_data;
				if (dir.GetAttribute(fl_data, res.file_id, FIRMLINK_EA_NAME) && !fl_data.empty())
				{
					std::string fl_path(reinterpret_cast<const char *>(fl_data.data()));
					ApfsVolume *data_vol = get_slot_volume(static_cast<uint8_t>(g_companion_data_slot));
					if (data_vol)
					{
						ApfsDir data_dir(*data_vol);
						uint64_t data_ino = 0;
						ApfsDir::Inode data_rec;
						if (data_dir.ResolvePath(fl_path, data_ino, data_rec))
							target_ino = make_ino(static_cast<uint8_t>(g_companion_data_slot), data_ino);
					}
				}
			}
		}

		fuse_entry_param e;
		memset(&e, 0, sizeof(e));

		e.ino = target_ino;
		e.attr_timeout = FUSE_TIMEOUT;
		e.entry_timeout = FUSE_TIMEOUT;

		rc = apfs_stat_internal(target_ino, e.attr);

		if (g_debug & Dbg_Info)
			std::cout << "    apfs_stat_internal " << target_ino << " => " << (rc ? "OK" : "FAIL") << std::endl;

		fuse_reply_entry(req, &e);
	}
}

static void apfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	if (g_debug & Dbg_Info)
		std::cout << std::hex << "apfs_open: " << ino << std::endl;

	bool rc;

	if ((fi->flags & 3) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
	{
		uint8_t slot = get_ino_slot(ino);
		uint64_t raw_ino = get_raw_ino(ino);
		ApfsVolume *vol = get_slot_volume(slot);
		if (!vol)
		{
			fuse_reply_err(req, ENOENT);
			return;
		}

		File *f = new File();
		f->vol = vol;
		ApfsDir dir(*vol);

		rc = dir.GetInode(f->ino, raw_ino);

		if (!rc)
		{
			std::cerr << "Couldn't get inode " << raw_ino << std::endl;
			fuse_reply_err(req, ENOENT);
			delete f;
			return;
		}

		if (f->IsCompressed())
		{
			std::vector<uint8_t> attr;

			rc = dir.GetAttribute(attr, raw_ino, "com.apple.decmpfs");

			if (!rc)
			{
				std::cerr << "Couldn't get attribute com.apple.decmpfs for " << raw_ino << std::endl;
				fuse_reply_err(req, ENOENT);
				delete f;
				return;
			}

			rc = DecompressFile(dir, raw_ino, f->decomp_data, attr);
			// In strict mode, do not return uncompressed data.
			if (!rc && !g_lax)
			{
				fuse_reply_err(req, EIO);
				delete f;
				return;
			}
		}

		fi->fh = reinterpret_cast<uint64_t>(f);

		fuse_reply_open(req, fi);
	}
}

static void apfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	if (g_debug & Dbg_Info)
		std::cout << std::hex << "apfs_opendir: " << ino << std::endl;

	Directory *dir = new Directory();

	fi->fh = reinterpret_cast<uint64_t>(dir);

	fuse_reply_open(req, fi);
}

static void apfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	File *file = reinterpret_cast<File *>(fi->fh);
	ApfsVolume *vol = (file && file->vol) ? file->vol : get_slot_volume(get_ino_slot(ino));
	ApfsDir dir(*vol);

	if (g_debug & Dbg_Info)
		std::cout << std::hex << "apfs_read: ino=" << ino << " size=" << size << " off=" << off << std::endl;

	if (!file->IsCompressed())
	{
		std::vector<char> buf(size, 0);
		dir.ReadFile(buf.data(), file->ino.private_id, off, size);
		fuse_reply_buf(req, buf.data(), buf.size());
	}
	else
	{
		if (static_cast<size_t>(off) >= file->decomp_data.size())
			size = 0;
		else if (off + size > file->decomp_data.size())
			size = file->decomp_data.size() - off;

		fuse_reply_buf(req, reinterpret_cast<const char *>(file->decomp_data.data()) + off, size);
	}
}

static void dirbuf_add(fuse_req_t req, std::vector<char> &dirbuf, const char *name, fuse_ino_t ino, mode_t mode)
{
	struct stat st;
	size_t oldsize;

	memset(&st, 0, sizeof(st));
	oldsize = dirbuf.size();
	dirbuf.resize(oldsize + fuse_add_direntry(req, nullptr, 0, name, nullptr, 0));
	st.st_ino = ino;
	st.st_mode = mode;
	fuse_add_direntry(req, &dirbuf[oldsize], dirbuf.size() - oldsize, name, &st, dirbuf.size());
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
	if (static_cast<size_t>(off) < bufsize)
		return fuse_reply_buf(req, buf + off, std::min(bufsize - static_cast<size_t>(off), maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}


static void apfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	std::vector<ApfsDir::DirRec> dir_list;
	Directory *dirptr = reinterpret_cast<Directory *>(fi->fh);
	std::vector<char> &dirbuf = dirptr->dirbuf;
	bool rc;

	if (g_debug & Dbg_Info)
		std::cout << "apfs_readdir: " << std::hex << ino << std::endl;

	if (dirbuf.size() == 0)
	{
		dirbuf.reserve(0x1000);

		// 1. Multi-volume container root directory
		if (g_all_volumes && ino == INO_VIRTUAL_CONTAINER_ROOT)
		{
			std::lock_guard<std::mutex> lock(g_slots_mutex);
			for (size_t i = 0; i < g_slots.size(); ++i)
			{
				if (g_slots[i].snap_xid == 0 && g_slots[i].vol)
					dirbuf_add(req, dirbuf, g_slots[i].label.c_str(), make_ino(static_cast<uint8_t>(i), ROOT_DIR_INO_NUM), S_IFDIR);
			}
			reply_buf_limited(req, dirbuf.data(), dirbuf.size(), off, size);
			return;
		}

		uint8_t slot = get_ino_slot(ino);
		uint64_t raw_ino = get_raw_ino(ino);
		ApfsVolume *vol = get_slot_volume(slot);
		if (!vol)
		{
			fuse_reply_err(req, ENOENT);
			return;
		}

		// 2. Virtual .snapshots directory
		if (is_virtual_snap_dir(ino))
		{
			std::vector<ApfsSnapshotInfo> snaps;
			vol->ListSnapshots(snaps);
			for (size_t i = 0; i < snaps.size(); ++i)
			{
				dirbuf_add(req, dirbuf, snaps[i].name.c_str(), make_ino(slot, 1000 + i), S_IFDIR);
			}
			reply_buf_limited(req, dirbuf.data(), dirbuf.size(), off, size);
			return;
		}

		ApfsDir dir(*vol);
		rc = dir.ListDirectory(dir_list, raw_ino);
		if (!rc)
		{
			fuse_reply_err(req, ENOENT);
			return;
		}

		if (raw_ino == ROOT_DIR_PARENT || raw_ino == ROOT_DIR_INO_NUM)
		{
			std::vector<ApfsSnapshotInfo> snaps;
			vol->ListSnapshots(snaps);
			if (!snaps.empty())
				dirbuf_add(req, dirbuf, ".snapshots", make_ino(slot, ROOT_DIR_INO_NUM, true), S_IFDIR);
		}

		for (size_t k = 0; k < dir_list.size(); k++)
			dirbuf_add(req, dirbuf, dir_list[k].name.c_str(), make_ino(slot, dir_list[k].file_id), (dir_list[k].flags & DREC_TYPE_MASK) << 12);
	}

	reply_buf_limited(req, dirbuf.data(), dirbuf.size(), off, size);
}

static void apfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
	ApfsVolume *vol = get_slot_volume(get_ino_slot(ino));
	if (!vol)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	ApfsDir dir(*vol);
	bool rc = false;
	std::vector<uint8_t> data;

	rc = dir.GetAttribute(data, get_raw_ino(ino), "com.apple.fs.symlink");
	if (!rc)
		rc = dir.GetAttribute(data, get_raw_ino(ino), FIRMLINK_EA_NAME);
	if (!rc)
		fuse_reply_err(req, ENOENT);
	else
	{
		data.push_back(0);
		fuse_reply_readlink(req, reinterpret_cast<const char *>(data.data()));
	}
}

static void apfs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (g_debug & Dbg_Info)
		std::cout << std::hex << "apfs_release " << ino << std::endl;

	File *file = reinterpret_cast<File *>(fi->fh);
	delete file;

	fuse_reply_err(req, 0);
}

static void apfs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (g_debug & Dbg_Info)
		std::cout << std::hex << "apfs_releasedir " << ino << std::endl;

	Directory *dir = reinterpret_cast<Directory *>(fi->fh);
	delete dir;

	fuse_reply_err(req, 0);
}

static void apfs_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct statvfs st;

	(void)ino;

	memset(&st, 0, sizeof(struct statvfs));

	st.f_bsize = g_container->GetBlocksize();
	st.f_frsize = st.f_bsize;
	st.f_blocks = g_container->GetBlockCount();
	st.f_bfree = g_container->GetFreeBlocks();
	st.f_bavail = st.f_bfree;

	st.f_files = 0;
	st.f_ffree = 0;
	st.f_favail = 0;

	st.f_fsid = 0;
	st.f_flag = 0;
	st.f_namemax = 255;

	fuse_reply_statfs(req, &st);
}

struct apfs {
	char *disk;
	char *logfile;
	int vol_id;
};

void usage(const char *name)
{
	std::cout << "APFS-Wonder (apfs-fuse) — Read-Only APFS FUSE Driver for Ubuntu & macOS Tahoe+" << std::endl;
	std::cout << "Usage: " << name << " [options] <device> <mountpoint>" << std::endl;
	std::cout << "   or: mount.apfs <device> <mountpoint> [-o options]" << std::endl;
	std::cout << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "-d level      : Enable debug output in the console." << std::endl;
	std::cout << "-f device     : Specify secondary device for fusion drives." << std::endl;
	std::cout << "-o options    : Additional mount options (see below)." << std::endl;
	std::cout << "-v volume-id  : Specify number of volume to be mounted." << std::endl;
	std::cout << "-a            : Mount all volumes in the container under /<VolumeName>." << std::endl;
	std::cout << "-r passphrase : Specify volume passphrase or Personal Recovery Key (PRK)." << std::endl;
	std::cout << "-s offset     : Specify byte offset to the beginning of the container." << std::endl;
	std::cout << "-p partition  : Specify GPT partition id containing the container." << std::endl;
	std::cout << "-l            : Lax mode: continue even if unexpected data is encountered." << std::endl;
	std::cout << std::endl;
	std::cout << "Additional mount options (using -o):" << std::endl;
	std::cout << "uid=N         : Pretend that all files have UID N." << std::endl;
	std::cout << "gid=N         : Pretend that all files have GID N." << std::endl;
	std::cout << "vol=N         : Same as -v, select volume id to mount." << std::endl;
	std::cout << "all_vols      : Same as -a, mount all container volumes." << std::endl;
	std::cout << "nofirmlinks   : Disable automatic System -> Data volume group firmlink stitching." << std::endl;
	std::cout << "cache_mb=N    : Set LRU decompression cache size in MiB (default: 128)." << std::endl;
	std::cout << "blksize=N     : Set physical block size (default: 512)." << std::endl;
	std::cout << "pass=...      : Specify volume passphrase (same as -r)." << std::endl;
	std::cout << "xid=N         : Mount specific container checkpoint xid." << std::endl;
	std::cout << "snap=N        : Mount snapshot with given xid (or browse /.snapshots live)." << std::endl;
	std::cout << std::endl;
}

bool add_option(std::string &optstr, const char *name, const char *value)
{
	if (!optstr.empty())
		optstr.push_back(',');
	optstr.append(name);
	if (value)
	{
		optstr.push_back('=');
		optstr.append(value);
	}

	return true;
}

static int apfs_parse_fuse_opt(void *data, const char *arg, int key, struct fuse_args* outargs)
{
	(void)data;
	(void)outargs;

	if (key == FUSE_OPT_KEY_OPT) {
		if (!strncmp(arg, "uid=", 4)) {
			g_uid = strtol(strchr(arg, '=') + sizeof(char), nullptr, 10);
			g_set_uid = true;
			return 0;
		}
		else if (!strncmp(arg, "gid=", 4)) {
			g_gid = strtol(strchr(arg, '=') + sizeof(char), nullptr, 10);
			g_set_gid = true;
			return 0;
		}
		else if (!strncmp(arg, "vol=", 4)) {
			g_vol_id = strtoul(strchr(arg, '=') + sizeof(char), nullptr, 10);
			return 0;
		}
		else if (!strcmp(arg, "all_vols")) {
			g_all_volumes = true;
			return 0;
		}
		else if (!strcmp(arg, "nofirmlinks")) {
			g_resolve_firmlinks = false;
			return 0;
		}
		else if (!strncmp(arg, "cache_mb=", 9)) {
			g_cache_mb = strtoull(strchr(arg, '=') + sizeof(char), nullptr, 10);
			return 0;
		}
		else if (!strncmp(arg, "blksize=", 8)) {
			g_physblksize = strtoul(strchr(arg, '=') + sizeof(char), nullptr, 10);
			return 0;
		}
		else if (!strncmp(arg, "pass=", 5)) {
			g_password = strchr(arg, '=') + sizeof(char);
			return 0;
		}
		else if (!strncmp(arg, "xid=", 4)) {
			g_xid = strtoull(strchr(arg, '=') + sizeof(char), nullptr, 10);
			return 0;
		}
		else if (!strncmp(arg, "snap=", 5)) {
			g_snap_xid = strtoull(strchr(arg, '=') + sizeof(char), nullptr, 10);
			return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
#ifdef USE_FUSE2
	struct fuse_chan *ch;
#else
	struct fuse_session *se;
#endif
	const char *mountpoint = nullptr;
	const char *main_dev_path = nullptr;
	const char *tier2_dev_path = nullptr;
	int err = -1;
	std::string mount_options;
	uint64_t main_offset = 0;
	uint64_t main_size = 0;
	uint64_t tier2_offset = 0;
	uint64_t tier2_size = 0;
	int partition_id = -1;

	memset(&ops, 0, sizeof(ops));

	ops.getattr = apfs_getattr;
	ops.getxattr = apfs_getxattr;
	ops.listxattr = apfs_listxattr;
	ops.lookup = apfs_lookup;
	ops.open = apfs_open;
	ops.opendir = apfs_opendir;
	ops.read = apfs_read;
	ops.readdir = apfs_readdir;
	ops.readlink = apfs_readlink;
	ops.release = apfs_release;
	ops.releasedir = apfs_releasedir;
	ops.statfs = apfs_statfs;

	g_uid = geteuid();
	g_gid = getegid();
	g_set_uid = false;
	g_set_gid = false;

	// Support both standard apfs-fuse [options] <dev> <mnt> AND mount.apfs <dev> <mnt> [-o opts]
	std::vector<const char *> positional;
	for (int i = 1; i < argc; ++i)
	{
		const char *a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help"))
		{
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(a, "--version"))
		{
			std::cout << "APFS-Wonder (apfs-fuse) 2.0.0" << std::endl;
			return 0;
		}
		if (!strcmp(a, "-a") || !strcmp(a, "--all-volumes"))
		{
			g_all_volumes = true;
		}
		else if (!strcmp(a, "-l"))
		{
			g_lax = true;
		}
		else if (!strcmp(a, "-n"))
		{
			// Ignored for /sbin/mount.apfs compatibility (do not write /etc/mtab)
		}
		else if (!strcmp(a, "-d") && (i + 1) < argc)
		{
			g_debug = strtoul(argv[++i], nullptr, 10);
		}
		else if (!strcmp(a, "-f") && (i + 1) < argc)
		{
			tier2_dev_path = argv[++i];
		}
		else if (!strcmp(a, "-o") && (i + 1) < argc)
		{
			add_option(mount_options, argv[++i], nullptr);
		}
		else if (!strcmp(a, "-p") && (i + 1) < argc)
		{
			partition_id = strtoul(argv[++i], nullptr, 10);
		}
		else if (!strcmp(a, "-v") && (i + 1) < argc)
		{
			g_vol_id = strtoul(argv[++i], nullptr, 10);
		}
		else if (!strcmp(a, "-r") && (i + 1) < argc)
		{
			g_password = argv[++i];
		}
		else if (!strcmp(a, "-s") && (i + 1) < argc)
		{
			main_offset = strtoull(argv[++i], nullptr, 10);
		}
		else if (a[0] == '-')
		{
			usage(argv[0]);
			return 1;
		}
		else
		{
			positional.push_back(a);
		}
	}

	if (positional.size() != 2)
	{
		usage(argv[0]);
		return 1;
	}

	main_dev_path = positional[0];
	mountpoint = positional[1];

	add_option(mount_options, "ro", nullptr);
	add_option(mount_options, "fsname", main_dev_path);

	fuse_opt_add_arg(&args, "apfs-fuse");
	fuse_opt_add_arg(&args, "-o");
	fuse_opt_add_arg(&args, mount_options.c_str());

	if (fuse_opt_parse(&args, NULL, NULL, apfs_parse_fuse_opt) != 0)
	{
		std::cerr << "Unable to parse mount options!" << std::endl;
	}

	ApfsDecompCache::Instance().SetMaxBytes(g_cache_mb * 1024ULL * 1024ULL);

	g_disk_main = Device::OpenDevice(main_dev_path);
	if (tier2_dev_path)
		g_disk_tier2 = Device::OpenDevice(tier2_dev_path);

	if (!g_disk_main)
	{
		std::cerr << "Error opening device!" << std::endl;
		return 1;
	}

	if (tier2_dev_path && !g_disk_tier2)
	{
		std::cerr << "Error opening secondary device!" << std::endl;
		return 1;
	}

	main_size = g_disk_main->GetSize();
	if (g_disk_tier2)
		tier2_size = g_disk_tier2->GetSize();

	if (main_offset >= main_size)
	{
		std::cerr << "Invalid container offset specified" << std::endl;
		g_disk_main->Close();
		delete g_disk_main;
		return 1;
	}

	if (g_physblksize != 512)
	{
		if (g_disk_main)
			g_disk_main->SetSectorSize(g_physblksize);
		if (g_disk_tier2)
			g_disk_tier2->SetSectorSize(g_physblksize);
	}

	if (main_offset == 0)
	{
		GptPartitionMap gpt;
		bool rc;

		rc = gpt.LoadAndVerify(*g_disk_main);
		if (rc)
		{
			if (g_debug & Dbg_Info)
				std::cout << "Found valid GPT partition table. Looking for APFS partition." << std::endl;

			if (partition_id == -1)
				partition_id = gpt.FindFirstAPFSPartition();

			if (partition_id != -1)
				gpt.GetPartitionOffsetAndSize(partition_id, main_offset, main_size);
		}
	}
	else
		main_size -= main_offset;

	if (g_disk_tier2)
	{
		GptPartitionMap gpt;

		if (gpt.LoadAndVerify(*g_disk_tier2))
		{
			if (g_debug & Dbg_Info)
				std::cout << "Found valid GPT partition table on secondary device. Looking for APFS partition." << std::endl;

			partition_id = gpt.FindFirstAPFSPartition();

			if (partition_id != -1)
				gpt.GetPartitionOffsetAndSize(partition_id, tier2_offset, tier2_size);
		}
	}

	g_container = new ApfsContainer(g_disk_main, main_offset, main_size, g_disk_tier2, tier2_offset, tier2_size);
	if (!g_container->Init(g_xid))
	{
		std::cerr << "Unable to load container." << std::endl;
		delete g_container;
		g_disk_main->Close();
		delete g_disk_main;
		return EINVAL;
	}

	if (g_all_volumes)
	{
		for (unsigned int fsid = 0; fsid < NX_MAX_FILE_SYSTEMS; ++fsid)
		{
			apfs_superblock_t apsb;
			if (!g_container->GetVolumeInfo(fsid, apsb))
				continue;

			std::unique_ptr<ApfsVolume> v(g_container->GetVolume(fsid, g_password, 0));
			if (!v)
				continue;

			VolumeSlot vs;
			vs.fsid = fsid;
			vs.snap_xid = 0;
			vs.label = v->name();
			if (vs.label.empty())
				vs.label = "Volume_" + std::to_string(fsid);
			if (!g_volume)
				g_volume = v.get();
			if (apsb.apfs_role == APFS_VOL_ROLE_DATA && g_companion_data_slot < 0)
				g_companion_data_slot = static_cast<int>(g_slots.size());
			vs.vol = std::move(v);
			g_slots.push_back(std::move(vs));
		}

		if (g_slots.empty())
		{
			std::cerr << "Unable to mount any volumes in container!" << std::endl;
			delete g_container;
			g_disk_main->Close();
			delete g_disk_main;
			return 1;
		}
	}
	else
	{
		std::unique_ptr<ApfsVolume> primary(g_container->GetVolume(g_vol_id, g_password, g_snap_xid));
		if (!primary)
		{
			std::cerr << "Unable to get volume!" << std::endl;
			delete g_container;
			g_disk_main->Close();
			delete g_disk_main;
			return 1;
		}
		g_volume = primary.get();
		uint16_t primary_role = primary->getSuperblock().apfs_role;
		apfs_uuid_t grp_id;
		memcpy(grp_id, primary->getSuperblock().apfs_volume_group_id, sizeof(apfs_uuid_t));

		VolumeSlot vs0;
		vs0.fsid = g_vol_id;
		vs0.snap_xid = g_snap_xid;
		vs0.label = primary->name();
		vs0.vol = std::move(primary);
		g_slots.push_back(std::move(vs0));

		// Auto-pair companion Data volume for System volume group firmlinks
		if (g_resolve_firmlinks && primary_role == APFS_VOL_ROLE_SYSTEM)
		{
			int data_fsid = g_container->FindVolumeByRole(APFS_VOL_ROLE_DATA, &grp_id);
			if (data_fsid < 0)
				data_fsid = g_container->FindVolumeByRole(APFS_VOL_ROLE_DATA, nullptr);
			if (data_fsid >= 0 && static_cast<unsigned int>(data_fsid) != g_vol_id)
			{
				std::unique_ptr<ApfsVolume> data_vol(g_container->GetVolume(static_cast<unsigned int>(data_fsid), g_password, 0));
				if (data_vol)
				{
					VolumeSlot vs_data;
					vs_data.fsid = static_cast<unsigned int>(data_fsid);
					vs_data.snap_xid = 0;
					vs_data.label = data_vol->name();
					vs_data.vol = std::move(data_vol);
					g_companion_data_slot = static_cast<int>(g_slots.size());
					g_slots.push_back(std::move(vs_data));
				}
			}
		}
	}

#ifdef USE_FUSE2
	if ((ch = fuse_mount(mountpoint, &args)) != NULL)
	{
		struct fuse_session *se;

		se = fuse_lowlevel_new(&args, &ops, sizeof(ops), NULL);
		if (se != NULL)
		{
			if (fuse_set_signal_handlers(se) != -1)
			{
				if (g_debug == 0)
					fuse_daemonize(0);
				fuse_session_add_chan(se, ch);
				err = fuse_session_loop(se);
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
#else
	se = fuse_session_new(&args, &ops, sizeof(ops), nullptr);
	if (se)
	{
		if (fuse_set_signal_handlers(se) != -1)
		{
			if (fuse_session_mount(se, mountpoint) == 0)
			{
				if (g_debug == 0)
					fuse_daemonize(0);

				err = fuse_session_loop(se);

				fuse_session_unmount(se);
			}
			fuse_remove_signal_handlers(se);
		}
		fuse_session_destroy(se);
	}
#endif
	fuse_opt_free_args(&args);

	g_slots.clear();
	g_volume = nullptr;
	delete g_container;
	g_disk_main->Close();
	delete g_disk_main;
	if (g_disk_tier2) {
		g_disk_tier2->Close();
		delete g_disk_tier2;
	}

	return err ? 1 : 0;
}
