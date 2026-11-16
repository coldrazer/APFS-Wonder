/*
	This file is part of APFS-Wonder (apfs-fuse), a read-only implementation
	of APFS (Apple File System) for FUSE & Forensics.
	SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/Decmpfs.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/KeyMgmt.h>
#include <ApfsLib/LruCache.h>
#include <ApfsLib/Util.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

static std::string json_escape(const std::string &s)
{
	std::ostringstream oss;
	for (unsigned char c : s)
	{
		switch (c)
		{
		case '"': oss << "\\\""; break;
		case '\\': oss << "\\\\"; break;
		case '\b': oss << "\\b"; break;
		case '\f': oss << "\\f"; break;
		case '\n': oss << "\\n"; break;
		case '\r': oss << "\\r"; break;
		case '\t': oss << "\\t"; break;
		default:
			if (c < 0x20)
				oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec;
			else
				oss << static_cast<char>(c);
			break;
		}
	}
	return oss.str();
}

static std::string role_to_string(uint16_t role)
{
	static const char *rolestr[] = {
		"System", "User", "Recovery", "VM", "Preboot", "Installer"
	};
	static const char *rolestr_enum[] = {
		"", "Data", "Baseband", "Update",
		"Xart", "Hardware", "Backup", "Reserved-7",
		"Reserved-8", "Enterprise", "Reserved-10", "Prelogin"
	};

	if (role == 0)
		return "No specific role";

	if (role <= 0x20)
	{
		std::string out;
		for (int k = 0; k < 6; k++)
		{
			if (role & (1 << k))
			{
				if (!out.empty())
					out += ", ";
				out += rolestr[k];
			}
		}
		return out;
	}

	if (role <= APFS_VOL_ROLE_PRELOGIN)
		return rolestr_enum[role >> APFS_VOLUME_ENUM_SHIFT];

	char buf[32];
	std::snprintf(buf, sizeof(buf), "Unknown (0x%04X)", role);
	return buf;
}

static void print_apfs_uuid(const apfs_uuid_t &uuid)
{
	printf("%02X%02X%02X%02X-", uuid[0], uuid[1], uuid[2], uuid[3]);
	printf("%02X%02X-", uuid[4], uuid[5]);
	printf("%02X%02X-", uuid[6], uuid[7]);
	printf("%02X%02X-", uuid[8], uuid[9]);
	printf("%02X%02X%02X%02X%02X%02X", uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static std::string mode_to_rwx(uint16_t mode)
{
	std::string s(10, '-');
	switch (mode & MODE_S_IFMT)
	{
	case MODE_S_IFDIR: s[0] = 'd'; break;
	case MODE_S_IFLNK: s[0] = 'l'; break;
	case MODE_S_IFCHR: s[0] = 'c'; break;
	case MODE_S_IFBLK: s[0] = 'b'; break;
	case MODE_S_IFIFO: s[0] = 'p'; break;
	case MODE_S_IFSOCK: s[0] = 's'; break;
	default: s[0] = '-'; break;
	}
	const char rwx[] = "rwx";
	for (int i = 0; i < 9; ++i)
	{
		if (mode & (1 << (8 - i)))
			s[1 + i] = rwx[i % 3];
	}
	return s;
}

static uint64_t get_logical_size(ApfsDir &dir, uint64_t ino, const ApfsDir::Inode &rec)
{
	if ((rec.mode & MODE_S_IFMT) == MODE_S_IFREG)
	{
		if (rec.bsd_flags & APFS_UF_COMPRESSED)
		{
			if (rec.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE)
				return rec.uncompressed_size;
			std::vector<uint8_t> data;
			if (dir.GetAttribute(data, ino, "com.apple.decmpfs") && data.size() >= sizeof(CompressionHeader))
			{
				const CompressionHeader *decmpfs = reinterpret_cast<const CompressionHeader *>(data.data());
				return decmpfs->size;
			}
		}
		if (rec.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM)
			return rec.ds_size;
	}
	return 0;
}

struct WalkEntry
{
	uint64_t ino;
	std::string path;
	ApfsDir::Inode rec;
};

static void walk_tree_recursive(ApfsDir &dir, uint64_t dir_ino, const std::string &prefix, std::vector<WalkEntry> &out, int depth = 0)
{
	if (depth > 32)
		return;

	std::vector<ApfsDir::DirRec> entries;
	if (!dir.ListDirectory(entries, dir_ino))
		return;

	for (const auto &e : entries)
	{
		if (e.name == "." || e.name == "..")
			continue;

		std::string full_path = prefix == "/" ? ("/" + e.name) : (prefix + "/" + e.name);
		ApfsDir::Inode rec;
		if (!dir.GetInode(rec, e.file_id))
			continue;

		out.push_back(WalkEntry{e.file_id, full_path, rec});

		if ((rec.mode & MODE_S_IFMT) == MODE_S_IFDIR)
			walk_tree_recursive(dir, e.file_id, full_path, out, depth + 1);
	}
}

static void print_tree_recursive(ApfsDir &dir, uint64_t dir_ino, const std::string &indent, int depth = 0)
{
	if (depth > 32)
		return;

	std::vector<ApfsDir::DirRec> entries;
	if (!dir.ListDirectory(entries, dir_ino))
		return;

	for (size_t i = 0; i < entries.size(); ++i)
	{
		const bool last = (i + 1 == entries.size());
		ApfsDir::Inode rec;
		bool has_ino = dir.GetInode(rec, entries[i].file_id);
		std::cout << indent << (last ? "└── " : "├── ") << entries[i].name;
		if (has_ino)
		{
			if (rec.bsd_flags & APFS_SF_FIRMLINK)
			{
				std::vector<uint8_t> fl;
				if (dir.GetAttribute(fl, entries[i].file_id, FIRMLINK_EA_NAME) && !fl.empty())
				{
					fl.push_back(0);
					std::cout << " -> [firmlink: " << reinterpret_cast<const char *>(fl.data()) << "]";
				}
			}
			else if ((rec.mode & MODE_S_IFMT) == MODE_S_IFLNK)
			{
				std::vector<uint8_t> sl;
				if (dir.GetAttribute(sl, entries[i].file_id, SYMLINK_EA_NAME) && !sl.empty())
				{
					sl.push_back(0);
					std::cout << " -> " << reinterpret_cast<const char *>(sl.data());
				}
			}
			else if (rec.bsd_flags & APFS_UF_COMPRESSED)
			{
				std::cout << " [decmpfs, " << get_logical_size(dir, entries[i].file_id, rec) << " B]";
			}
		}
		std::cout << "\n";

		if (has_ino && (rec.mode & MODE_S_IFMT) == MODE_S_IFDIR)
			print_tree_recursive(dir, entries[i].file_id, indent + (last ? "    " : "│   "), depth + 1);
	}
}

static bool extract_recursive(ApfsDir &dir, uint64_t ino, const ApfsDir::Inode &rec, const std::string &dst_path, uint64_t &files_extracted, uint64_t &bytes_extracted)
{
	uint16_t ftype = rec.mode & MODE_S_IFMT;
	if (ftype == MODE_S_IFDIR)
	{
		mkdir(dst_path.c_str(), 0755);
		std::vector<ApfsDir::DirRec> children;
		if (!dir.ListDirectory(children, ino))
			return false;
		for (const auto &c : children)
		{
			if (c.name == "." || c.name == "..")
				continue;
			ApfsDir::Inode crec;
			if (!dir.GetInode(crec, c.file_id))
				continue;
			extract_recursive(dir, c.file_id, crec, dst_path + "/" + c.name, files_extracted, bytes_extracted);
		}
		return true;
	}
	else if (ftype == MODE_S_IFLNK)
	{
		std::vector<uint8_t> sl;
		if (dir.GetAttribute(sl, ino, SYMLINK_EA_NAME) && !sl.empty())
		{
			sl.push_back(0);
			unlink(dst_path.c_str());
			symlink(reinterpret_cast<const char *>(sl.data()), dst_path.c_str());
			files_extracted++;
			return true;
		}
		return false;
	}
	else if (ftype == MODE_S_IFREG)
	{
		std::vector<uint8_t> data;
		if (!dir.ReadFileSmart(data, ino, rec))
			return false;
		std::ofstream ofs(dst_path, std::ios::binary | std::ios::trunc);
		if (!ofs.is_open())
			return false;
		if (!data.empty())
			ofs.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
		ofs.close();
		chmod(dst_path.c_str(), rec.mode & 0777);
		files_extracted++;
		bytes_extracted += data.size();
		return true;
	}
	return true;
}

static void print_usage(const char *prog)
{
	std::cout << "APFS-Wonder (apfsutil) — Cross-Platform APFS Inspector, Extractor & Forensics CLI\n\n"
	          << "Usage:\n"
	          << "  " << prog << " <device> [--json]                                  Show container, volume & snapshot summary\n"
	          << "  " << prog << " info <device> [--json]                             Show container, volume & snapshot summary\n"
	          << "  " << prog << " ls <device> [path] [-v vol] [--snap xid] [--json]  List directory contents without FUSE\n"
	          << "  " << prog << " tree <device> [path] [-v vol]                      Display directory tree hierarchy\n"
	          << "  " << prog << " stat <device> <path> [-v vol] [--json]             Inspect inode metadata & extended attributes\n"
	          << "  " << prog << " cat <device> <path> [-v vol]                       Stream file content (transparent decompression)\n"
	          << "  " << prog << " extract <device> <src-path> <dst-path> [-v vol]    Extract file or directory tree to host\n"
	          << "  " << prog << " find <device> [pattern] [-v vol] [--json]          Search file paths across volume\n"
	          << "  " << prog << " xids <device> [--json]                             List all checkpoint transactions in ring buffer\n"
	          << "  " << prog << " carve <device> [--xid old_xid] [out-dir] [--json]  Diff checkpoints & recover deleted/modified files\n"
	          << "  " << prog << " keybag <device> [--verify-pass <pw>] [--json]      Inspect FileVault keybags & test passphrase/PRK\n"
	          << "  " << prog << " integrity-check <device> [-v vol] [--json]         Verify Sealed Volume (SSV) & file data hashes\n"
	          << "  " << prog << " bench <device> [-v vol] [--iterations N] [--json]  Run B-tree, decompression & LRU cache benchmarks\n";
}

} // namespace

int main(int argc, char *argv[])
{
	g_debug = 0;

	if (argc < 2)
	{
		print_usage(argv[0]);
		return EINVAL;
	}

	std::string cmd = "info";
	std::vector<std::string> pos;
	unsigned int vol_id = 0;
	xid_t req_xid = 0;
	xid_t snap_xid = 0;
	bool json_mode = false;
	std::string verify_pass;
	int iterations = 50;

	static const std::set<std::string> known_cmds = {
		"info", "ls", "tree", "stat", "cat", "extract", "find",
		"xids", "carve", "keybag", "integrity-check", "bench"
	};

	int arg_start = 1;
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
	{
		print_usage(argv[0]);
		return 0;
	}
	if (known_cmds.count(argv[1]))
	{
		cmd = argv[1];
		arg_start = 2;
	}

	for (int i = arg_start; i < argc; ++i)
	{
		std::string a = argv[i];
		if (a == "--json" || a == "-j")
			json_mode = true;
		else if ((a == "-v" || a == "--vol") && (i + 1) < argc)
			vol_id = static_cast<unsigned int>(std::strtoul(argv[++i], nullptr, 10));
		else if (a == "--xid" && (i + 1) < argc)
			req_xid = std::strtoull(argv[++i], nullptr, 10);
		else if (a == "--snap" && (i + 1) < argc)
			snap_xid = std::strtoull(argv[++i], nullptr, 10);
		else if ((a == "--verify-pass" || a == "-r") && (i + 1) < argc)
			verify_pass = argv[++i];
		else if (a == "--iterations" && (i + 1) < argc)
			iterations = std::max(1, std::atoi(argv[++i]));
		else if (a == "-h" || a == "--help")
		{
			print_usage(argv[0]);
			return 0;
		}
		else
			pos.push_back(a);
	}

	if (pos.empty())
	{
		print_usage(argv[0]);
		return EINVAL;
	}

	const char *devname = pos[0].c_str();
	std::unique_ptr<Device> device(Device::OpenDevice(devname));
	if (!device)
	{
		if (json_mode)
			std::cout << "{\"error\":\"Error opening device\"}\n";
		else
			printf("Error opening device.\n");
		return EIO;
	}

	uint64_t offset = 0;
	uint64_t size = device->GetSize();

	GptPartitionMap gpt;
	bool has_gpt = gpt.LoadAndVerify(*device);
	int first_apfs_part = -1;
	if (has_gpt)
	{
		first_apfs_part = gpt.FindFirstAPFSPartition();
		if (first_apfs_part >= 0)
			gpt.GetPartitionOffsetAndSize(first_apfs_part, offset, size);
	}

	// For non-carve commands, init with req_xid (0 = latest)
	std::unique_ptr<ApfsContainer> container(new ApfsContainer(device.get(), offset, size));
	if (!container->Init(cmd == "carve" ? 0 : req_xid))
	{
		if (json_mode)
			std::cout << "{\"error\":\"Unable to open APFS container\"}\n";
		else
			printf("Unable to open APFS container\n");
		device->Close();
		return EIO;
	}

	// 1. INFO command
	if (cmd == "info")
	{
		apfs_superblock_t apsb;
		if (json_mode)
		{
			const nx_superblock_t &nx = container->GetSuperblock();
			std::cout << "{\n"
			          << "  \"container\": {\n"
			          << "    \"uuid\": \"" << uuidstr(nx.nx_uuid) << "\",\n"
			          << "    \"xid\": " << nx.nx_o.o_xid << ",\n"
			          << "    \"block_size\": " << container->GetBlocksize() << ",\n"
			          << "    \"block_count\": " << container->GetBlockCount() << ",\n"
			          << "    \"free_blocks\": " << container->GetFreeBlocks() << "\n"
			          << "  },\n"
			          << "  \"volumes\": [\n";
			bool first_vol = true;
			for (int k = 0; k < NX_MAX_FILE_SYSTEMS; k++)
			{
				if (!container->GetVolumeInfo(k, apsb))
					continue;
				if (!first_vol)
					std::cout << ",\n";
				first_vol = false;

				std::string vname(reinterpret_cast<const char *>(apsb.apfs_volname));
				bool case_insensitive = (apsb.apfs_incompatible_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0;
				bool sealed = (apsb.apfs_incompatible_features & APFS_INCOMPAT_SEALED_VOLUME) != 0;
				bool encrypted = (apsb.apfs_fs_flags & APFS_FS_CRYPTOFLAGS) != 1;

				std::cout << "    {\n"
				          << "      \"index\": " << k << ",\n"
				          << "      \"uuid\": \"" << uuidstr(apsb.apfs_vol_uuid) << "\",\n"
				          << "      \"volume_group_id\": \"" << uuidstr(apsb.apfs_volume_group_id) << "\",\n"
				          << "      \"name\": \"" << json_escape(vname) << "\",\n"
				          << "      \"role\": \"" << json_escape(role_to_string(apsb.apfs_role)) << "\",\n"
				          << "      \"case_insensitive\": " << (case_insensitive ? "true" : "false") << ",\n"
				          << "      \"sealed\": " << (sealed ? "true" : "false") << ",\n"
				          << "      \"filevault\": " << (encrypted ? "true" : "false") << ",\n"
				          << "      \"capacity_consumed_bytes\": " << (apsb.apfs_fs_alloc_count * container->GetBlocksize()) << ",\n"
				          << "      \"num_files\": " << apsb.apfs_num_files << ",\n"
				          << "      \"num_directories\": " << apsb.apfs_num_directories << ",\n"
				          << "      \"snapshots\": [";

				if (apsb.apfs_snap_meta_tree_oid)
				{
					BTree snap_tree(*container);
					BTreeIterator it;
					BTreeEntry bte;
					snap_tree.Init(apsb.apfs_snap_meta_tree_oid, apsb.apfs_o.o_xid);
					bool first_snap = true;
					if (snap_tree.GetIteratorBegin(it))
					{
						for (;;)
						{
							if (!it.GetEntry(bte))
								break;
							const j_snap_metadata_key_t *sme_k = reinterpret_cast<const j_snap_metadata_key_t *>(bte.key);
							const j_snap_metadata_val_t *sme_v = reinterpret_cast<const j_snap_metadata_val_t *>(bte.val);
							if ((sme_k->hdr.obj_id_and_type >> OBJ_TYPE_SHIFT) != APFS_TYPE_SNAP_METADATA)
								break;
							if (!first_snap)
								std::cout << ", ";
							first_snap = false;
							std::cout << "{\"xid\": " << (sme_k->hdr.obj_id_and_type & OBJ_ID_MASK)
							          << ", \"name\": \"" << json_escape(reinterpret_cast<const char *>(sme_v->name)) << "\"}";
							if (!it.next())
								break;
						}
					}
				}
				std::cout << "]\n    }";
			}
			std::cout << "\n  ]\n}\n";
		}
		else
		{
			if (has_gpt)
			{
				printf("Found partitions:\n");
				gpt.ListEntries();
				if (first_apfs_part >= 0)
					printf("First APFS partition is %d\n", first_apfs_part);
				printf("\n");
			}

			for (int k = 0; k < NX_MAX_FILE_SYSTEMS; k++)
			{
				if (!container->GetVolumeInfo(k, apsb))
					continue;
				printf("Volume %d ", k);
				print_apfs_uuid(apsb.apfs_vol_uuid);
				printf("\n---------------------------------------------\n");
				printf("Role:               %s\n", role_to_string(apsb.apfs_role).c_str());
				printf("Name:               %s", apsb.apfs_volname);
				if (apsb.apfs_incompatible_features & APFS_INCOMPAT_CASE_INSENSITIVE)
					printf(" (Case-insensitive)\n");
				else if (apsb.apfs_incompatible_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE)
					printf(" (Case-sensitive)\n");
				else
					printf("\n");
				printf("Capacity Consumed:  %" PRIu64 " Bytes\n", apsb.apfs_fs_alloc_count * container->GetBlocksize());
				printf("FileVault:          %s\n", ((apsb.apfs_fs_flags & APFS_FS_CRYPTOFLAGS) == 1) ? "No" : "Yes");
				if (apsb.apfs_snap_meta_tree_oid)
				{
					printf("Snapshots:\n");
					BTree snap_tree(*container);
					BTreeIterator it;
					BTreeEntry bte;
					snap_tree.Init(apsb.apfs_snap_meta_tree_oid, apsb.apfs_o.o_xid);
					if (snap_tree.GetIteratorBegin(it))
					{
						for (;;)
						{
							if (!it.GetEntry(bte))
								break;
							const j_snap_metadata_key_t *sme_k = reinterpret_cast<const j_snap_metadata_key_t *>(bte.key);
							const j_snap_metadata_val_t *sme_v = reinterpret_cast<const j_snap_metadata_val_t *>(bte.val);
							if ((sme_k->hdr.obj_id_and_type >> OBJ_TYPE_SHIFT) != APFS_TYPE_SNAP_METADATA)
								break;
							printf("    %" PRIu64 " : '%s'\n", sme_k->hdr.obj_id_and_type & OBJ_ID_MASK, sme_v->name);
							if (!it.next())
								break;
						}
					}
				}
				printf("\n");
			}
		}
		device->Close();
		return 0;
	}

	// 2. XIDS command (Add-On #6)
	if (cmd == "xids")
	{
		std::vector<ApfsCheckpointInfo> cps;
		container->ListCheckpoints(cps);
		if (json_mode)
		{
			std::cout << "{\n  \"checkpoints\": [\n";
			for (size_t i = 0; i < cps.size(); ++i)
			{
				if (i > 0)
					std::cout << ",\n";
				std::cout << "    {\"xid\": " << cps[i].xid
				          << ", \"paddr\": " << cps[i].paddr
				          << ", \"next_oid\": " << cps[i].next_oid
				          << ", \"xp_desc_index\": " << cps[i].xp_desc_index
				          << ", \"xp_data_index\": " << cps[i].xp_data_index
				          << ", \"is_active\": " << (cps[i].is_active ? "true" : "false") << "}";
			}
			std::cout << "\n  ]\n}\n";
		}
		else
		{
			std::cout << "Checkpoints in NX descriptor ring (" << cps.size() << " found):\n";
			std::cout << "XID        | PAddr      | Next OID   | Desc Idx | Data Idx | Status\n";
			std::cout << "-----------+------------+------------+----------+----------+--------\n";
			for (const auto &c : cps)
			{
				printf("%-10" PRIu64 " | %-10" PRIu64 " | %-10" PRIu64 " | %-8u | %-8u | %s\n",
				       c.xid, c.paddr, c.next_oid, c.xp_desc_index, c.xp_data_index,
				       c.is_active ? "ACTIVE (latest)" : "historical");
			}
		}
		device->Close();
		return 0;
	}

	// 3. KEYBAG command (Add-On #9)
	if (cmd == "keybag")
	{
		KeyManager &km = container->GetKeyManager();
		std::vector<ApfsKeybagEntryInfo> entries;
		km.GetKeybagInfo(entries);

		bool pass_tested = !verify_pass.empty();
		bool pass_ok = false;
		std::string tested_vol_uuid;

		if (pass_tested)
		{
			apfs_superblock_t apsb;
			if (container->GetVolumeInfo(vol_id, apsb))
			{
				tested_vol_uuid = uuidstr(apsb.apfs_vol_uuid);
				uint8_t vek[0x20];
				pass_ok = container->GetVolumeKey(vek, apsb.apfs_vol_uuid, verify_pass.c_str());
			}
		}

		if (json_mode)
		{
			std::cout << "{\n"
			          << "  \"keybag_valid\": " << (km.IsValid() ? "true" : "false") << ",\n"
			          << "  \"unencrypted_keybag\": " << (km.IsUnencrypted() ? "true" : "false") << ",\n";
			if (pass_tested)
			{
				std::cout << "  \"password_verification\": {\"volume_uuid\": \"" << tested_vol_uuid
				          << "\", \"valid\": " << (pass_ok ? "true" : "false") << "},\n";
			}
			std::cout << "  \"entries\": [\n";
			for (size_t i = 0; i < entries.size(); ++i)
			{
				if (i > 0)
					std::cout << ",\n";
				std::cout << "    {\"scope\": \"" << entries[i].scope
				          << "\", \"uuid\": \"" << entries[i].uuid
				          << "\", \"tag\": " << entries[i].tag
				          << ", \"tag_name\": \"" << entries[i].tag_name
				          << "\", \"keylen\": " << entries[i].keylen
				          << ", \"hint\": \"" << json_escape(entries[i].hint) << "\"}";
			}
			std::cout << "\n  ]\n}\n";
		}
		else
		{
			if (!km.IsValid())
			{
				std::cout << "No encrypted keybag present on this container (unencrypted container).\n";
			}
			else
			{
				km.dump(std::cout);
				if (pass_tested)
				{
					std::cout << "Password/PRK verification for volume " << vol_id << " (" << tested_vol_uuid << "): "
					          << (pass_ok ? "VALID (VEK successfully unwrapped)" : "INVALID") << "\n";
				}
			}
		}
		device->Close();
		return pass_tested && !pass_ok ? 1 : 0;
	}

	// 4. CARVE command (Add-On #6: Checkpoint Rollback Diff & Deleted File Recovery)
	if (cmd == "carve")
	{
		std::vector<ApfsCheckpointInfo> cps;
		container->ListCheckpoints(cps);
		xid_t latest_xid = container->GetSuperblock().nx_o.o_xid;
		xid_t target_old_xid = req_xid;
		if (target_old_xid == 0 && cps.size() >= 2)
			target_old_xid = cps.front().xid;

		std::unique_ptr<ApfsVolume> cur_vol(container->GetVolume(vol_id, verify_pass));
		if (!cur_vol)
		{
			std::cerr << "Unable to open current volume\n";
			device->Close();
			return 1;
		}
		ApfsDir cur_dir(*cur_vol);
		std::vector<WalkEntry> cur_files;
		walk_tree_recursive(cur_dir, ROOT_DIR_INO_NUM, "/", cur_files);
		std::map<std::string, uint64_t> cur_paths;
		for (const auto &f : cur_files)
			cur_paths[f.path] = f.rec.mod_time;

		std::vector<WalkEntry> recovered_candidates;
		if (target_old_xid != 0 && target_old_xid != latest_xid)
		{
			ApfsContainer old_container(device.get(), offset, size);
			if (old_container.Init(target_old_xid))
			{
				std::unique_ptr<ApfsVolume> old_vol(old_container.GetVolume(vol_id, verify_pass));
				if (old_vol)
				{
					ApfsDir old_dir(*old_vol);
					std::vector<WalkEntry> old_files;
					walk_tree_recursive(old_dir, ROOT_DIR_INO_NUM, "/", old_files);
					for (const auto &of : old_files)
					{
						if (cur_paths.find(of.path) == cur_paths.end())
						{
							recovered_candidates.push_back(of);
							if (pos.size() >= 2 && (of.rec.mode & MODE_S_IFMT) == MODE_S_IFREG)
							{
								std::string out_dir = pos[1];
								mkdir(out_dir.c_str(), 0755);
								std::string flat_name = of.path.substr(1);
								std::replace(flat_name.begin(), flat_name.end(), '/', '_');
								uint64_t f_ext = 0, b_ext = 0;
								extract_recursive(old_dir, of.ino, of.rec, out_dir + "/" + flat_name, f_ext, b_ext);
							}
						}
					}
				}
			}
		}

		if (json_mode)
		{
			std::cout << "{\n"
			          << "  \"latest_xid\": " << latest_xid << ",\n"
			          << "  \"compared_xid\": " << target_old_xid << ",\n"
			          << "  \"checkpoints_available\": " << cps.size() << ",\n"
			          << "  \"deleted_files_found\": " << recovered_candidates.size() << ",\n"
			          << "  \"deleted_entries\": [";
			for (size_t i = 0; i < recovered_candidates.size(); ++i)
			{
				if (i > 0)
					std::cout << ", ";
				std::cout << "{\"ino\": " << recovered_candidates[i].ino
				          << ", \"path\": \"" << json_escape(recovered_candidates[i].path) << "\"}";
			}
			std::cout << "]\n}\n";
		}
		else
		{
			std::cout << "Checkpoint Forensics: compared XID " << target_old_xid << " -> latest XID " << latest_xid
			          << " (" << cps.size() << " checkpoints in ring)\n";
			std::cout << "Deleted entries recoverable from historical checkpoint: " << recovered_candidates.size() << "\n";
			for (const auto &rc : recovered_candidates)
				std::cout << "  [DELETED] ino=" << rc.ino << " " << rc.path << "\n";
		}
		device->Close();
		return 0;
	}

	// Open target volume (and optional companion Data volume for firmlinks)
	std::unique_ptr<ApfsVolume> vol(container->GetVolume(vol_id, verify_pass, snap_xid));
	if (!vol)
	{
		if (json_mode)
			std::cout << "{\"error\":\"Unable to open volume\"}\n";
		else
			std::cerr << "Unable to open volume " << vol_id << "\n";
		device->Close();
		return 1;
	}

	std::unique_ptr<ApfsVolume> companion_data_vol;
	std::unique_ptr<ApfsDir> companion_data_dir;
	if (vol->getSuperblock().apfs_role == APFS_VOL_ROLE_SYSTEM)
	{
		int data_fsid = container->FindVolumeByRole(APFS_VOL_ROLE_DATA, &vol->getSuperblock().apfs_volume_group_id);
		if (data_fsid < 0)
			data_fsid = container->FindVolumeByRole(APFS_VOL_ROLE_DATA, nullptr);
		if (data_fsid >= 0 && static_cast<unsigned int>(data_fsid) != vol_id)
		{
			companion_data_vol.reset(container->GetVolume(static_cast<unsigned int>(data_fsid), verify_pass, 0));
			if (companion_data_vol)
				companion_data_dir.reset(new ApfsDir(*companion_data_vol));
		}
	}

	ApfsDir dir(*vol);

	// 5. LS command (Add-On #1)
	if (cmd == "ls")
	{
		std::string path = (pos.size() >= 2) ? pos[1] : "/";
		uint64_t target_ino = ROOT_DIR_INO_NUM;
		ApfsDir::Inode target_rec;
		bool in_companion = false;
		if (!dir.ResolvePath(path, target_ino, target_rec, companion_data_dir.get(), &in_companion))
		{
			std::cerr << "Path not found: " << path << "\n";
			device->Close();
			return ENOENT;
		}
		ApfsDir &active_dir = (in_companion && companion_data_dir) ? *companion_data_dir : dir;

		std::vector<ApfsDir::DirRec> entries;
		if (!active_dir.ListDirectory(entries, target_ino))
		{
			std::cerr << "Unable to list directory: " << path << "\n";
			device->Close();
			return EIO;
		}

		if (json_mode)
		{
			std::cout << "{\n  \"path\": \"" << json_escape(path) << "\",\n  \"entries\": [\n";
			for (size_t i = 0; i < entries.size(); ++i)
			{
				ApfsDir::Inode irec;
				active_dir.GetInode(irec, entries[i].file_id);
				uint64_t fsize = get_logical_size(active_dir, entries[i].file_id, irec);
				if (i > 0)
					std::cout << ",\n";
				std::cout << "    {\"ino\": " << entries[i].file_id
				          << ", \"name\": \"" << json_escape(entries[i].name)
				          << "\", \"mode\": \"" << mode_to_rwx(irec.mode)
				          << "\", \"size\": " << fsize
				          << ", \"compressed\": " << ((irec.bsd_flags & APFS_UF_COMPRESSED) ? "true" : "false")
				          << ", \"firmlink\": " << ((irec.bsd_flags & APFS_SF_FIRMLINK) ? "true" : "false") << "}";
			}
			std::cout << "\n  ]\n}\n";
		}
		else
		{
			for (const auto &e : entries)
			{
				ApfsDir::Inode irec;
				active_dir.GetInode(irec, e.file_id);
				uint64_t fsize = get_logical_size(active_dir, e.file_id, irec);
				printf("%s  %8" PRIu64 "  %10" PRIu64 "  %s\n",
				       mode_to_rwx(irec.mode).c_str(), e.file_id, fsize, e.name.c_str());
			}
		}
		device->Close();
		return 0;
	}

	// 6. TREE command (Add-On #1)
	if (cmd == "tree")
	{
		std::string path = (pos.size() >= 2) ? pos[1] : "/";
		uint64_t target_ino = ROOT_DIR_INO_NUM;
		ApfsDir::Inode target_rec;
		bool in_companion = false;
		if (!dir.ResolvePath(path, target_ino, target_rec, companion_data_dir.get(), &in_companion))
		{
			std::cerr << "Path not found: " << path << "\n";
			device->Close();
			return ENOENT;
		}
		ApfsDir &active_dir = (in_companion && companion_data_dir) ? *companion_data_dir : dir;
		std::cout << path << "\n";
		print_tree_recursive(active_dir, target_ino, "");
		device->Close();
		return 0;
	}

	// 7. STAT command (Add-On #1 & #8)
	if (cmd == "stat")
	{
		if (pos.size() < 2)
		{
			std::cerr << "Usage: apfsutil stat <device> <path>\n";
			device->Close();
			return EINVAL;
		}
		uint64_t target_ino = 0;
		ApfsDir::Inode rec;
		bool in_companion = false;
		if (!dir.ResolvePath(pos[1], target_ino, rec, companion_data_dir.get(), &in_companion))
		{
			std::cerr << "Path not found: " << pos[1] << "\n";
			device->Close();
			return ENOENT;
		}
		ApfsDir &active_dir = (in_companion && companion_data_dir) ? *companion_data_dir : dir;
		std::vector<std::string> xattrs;
		active_dir.ListAttributes(xattrs, target_ino);
		uint64_t fsize = get_logical_size(active_dir, target_ino, rec);

		if (json_mode)
		{
			std::cout << "{\n"
			          << "  \"path\": \"" << json_escape(pos[1]) << "\",\n"
			          << "  \"ino\": " << target_ino << ",\n"
			          << "  \"private_id\": " << rec.private_id << ",\n"
			          << "  \"mode\": \"" << mode_to_rwx(rec.mode) << "\",\n"
			          << "  \"uid\": " << rec.owner << ",\n"
			          << "  \"gid\": " << rec.group << ",\n"
			          << "  \"size\": " << fsize << ",\n"
			          << "  \"bsd_flags\": " << rec.bsd_flags << ",\n"
			          << "  \"compressed\": " << ((rec.bsd_flags & APFS_UF_COMPRESSED) ? "true" : "false") << ",\n"
			          << "  \"firmlink\": " << ((rec.bsd_flags & APFS_SF_FIRMLINK) ? "true" : "false") << ",\n"
			          << "  \"xattrs\": [";
			for (size_t i = 0; i < xattrs.size(); ++i)
			{
				if (i > 0)
					std::cout << ", ";
				std::cout << "\"" << json_escape(xattrs[i]) << "\"";
			}
			std::cout << "]\n}\n";
		}
		else
		{
			std::cout << "  Path: " << pos[1] << "\n"
			          << " Inode: " << target_ino << " (private_id=" << rec.private_id << ")\n"
			          << "  Mode: " << mode_to_rwx(rec.mode) << " (0" << std::oct << (rec.mode & 07777) << std::dec << ")\n"
			          << " Owner: uid=" << rec.owner << " gid=" << rec.group << "\n"
			          << "  Size: " << fsize << " bytes\n"
			          << " Flags: 0x" << std::hex << rec.bsd_flags << std::dec
			          << ((rec.bsd_flags & APFS_UF_COMPRESSED) ? " [UF_COMPRESSED]" : "")
			          << ((rec.bsd_flags & APFS_SF_FIRMLINK) ? " [SF_FIRMLINK]" : "") << "\n"
			          << "XAttrs: " << xattrs.size() << "\n";
			for (const auto &xa : xattrs)
				std::cout << "  - " << xa << "\n";
		}
		device->Close();
		return 0;
	}

	// 8. CAT command (Add-On #1)
	if (cmd == "cat")
	{
		if (pos.size() < 2)
		{
			std::cerr << "Usage: apfsutil cat <device> <path>\n";
			device->Close();
			return EINVAL;
		}
		uint64_t target_ino = 0;
		ApfsDir::Inode rec;
		bool in_companion = false;
		if (!dir.ResolvePath(pos[1], target_ino, rec, companion_data_dir.get(), &in_companion))
		{
			std::cerr << "Path not found: " << pos[1] << "\n";
			device->Close();
			return ENOENT;
		}
		ApfsDir &active_dir = (in_companion && companion_data_dir) ? *companion_data_dir : dir;
		std::vector<uint8_t> data;
		if (!active_dir.ReadFileSmart(data, target_ino, rec))
		{
			std::cerr << "Failed to read file: " << pos[1] << "\n";
			device->Close();
			return EIO;
		}
		if (!data.empty())
			std::cout.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
		device->Close();
		return 0;
	}

	// 9. EXTRACT command (Add-On #1)
	if (cmd == "extract")
	{
		if (pos.size() < 3)
		{
			std::cerr << "Usage: apfsutil extract <device> <src-path> <dst-path>\n";
			device->Close();
			return EINVAL;
		}
		uint64_t target_ino = 0;
		ApfsDir::Inode rec;
		bool in_companion = false;
		if (!dir.ResolvePath(pos[1], target_ino, rec, companion_data_dir.get(), &in_companion))
		{
			std::cerr << "Source path not found: " << pos[1] << "\n";
			device->Close();
			return ENOENT;
		}
		ApfsDir &active_dir = (in_companion && companion_data_dir) ? *companion_data_dir : dir;
		uint64_t files_extracted = 0;
		uint64_t bytes_extracted = 0;
		bool ok = extract_recursive(active_dir, target_ino, rec, pos[2], files_extracted, bytes_extracted);
		if (json_mode)
		{
			std::cout << "{\"ok\":" << (ok ? "true" : "false")
			          << ",\"files_extracted\":" << files_extracted
			          << ",\"bytes_extracted\":" << bytes_extracted << "}\n";
		}
		else
		{
			std::cout << "Extracted " << files_extracted << " item(s) (" << bytes_extracted << " bytes) to " << pos[2] << "\n";
		}
		device->Close();
		return ok ? 0 : 1;
	}

	// 10. FIND command (Add-On #1)
	if (cmd == "find")
	{
		std::string pattern = (pos.size() >= 2) ? pos[1] : "";
		std::vector<WalkEntry> all;
		walk_tree_recursive(dir, ROOT_DIR_INO_NUM, "/", all);
		std::vector<WalkEntry> matched;
		for (const auto &e : all)
		{
			if (pattern.empty() || e.path.find(pattern) != std::string::npos)
				matched.push_back(e);
		}
		if (json_mode)
		{
			std::cout << "{\n  \"matches\": [\n";
			for (size_t i = 0; i < matched.size(); ++i)
			{
				if (i > 0)
					std::cout << ",\n";
				std::cout << "    {\"ino\": " << matched[i].ino << ", \"path\": \"" << json_escape(matched[i].path) << "\"}";
			}
			std::cout << "\n  ]\n}\n";
		}
		else
		{
			for (const auto &m : matched)
				std::cout << m.path << "\n";
		}
		device->Close();
		return 0;
	}

	// 11. INTEGRITY-CHECK command (Add-On #5)
	if (cmd == "integrity-check")
	{
		integrity_meta_phys_t im = {};
		std::vector<uint8_t> root_hash;
		bool has_im = vol->GetIntegrityMeta(im, root_hash);

		std::vector<WalkEntry> all;
		walk_tree_recursive(dir, ROOT_DIR_INO_NUM, "/", all);

		uint64_t files_checked = 0;
		uint64_t files_passed = 0;
		uint64_t files_failed = 0;
		uint64_t total_bytes = 0;
		uint64_t total_hash_records = 0;

		for (const auto &e : all)
		{
			if ((e.rec.mode & MODE_S_IFMT) != MODE_S_IFREG)
				continue;
			files_checked++;
			uint64_t vbytes = 0, hrecs = 0;
			if (dir.VerifyFileIntegrity(e.ino, vbytes, hrecs))
			{
				files_passed++;
				total_bytes += vbytes;
				total_hash_records += hrecs;
			}
			else
			{
				files_failed++;
			}
		}

		if (json_mode)
		{
			std::cout << "{\n"
			          << "  \"sealed_volume\": " << (vol->isSealed() ? "true" : "false") << ",\n"
			          << "  \"has_integrity_meta\": " << (has_im ? "true" : "false") << ",\n"
			          << "  \"seal_broken\": " << ((has_im && (im.im_flags & APFS_SEAL_BROKEN)) ? "true" : "false") << ",\n"
			          << "  \"root_hash\": \"" << (root_hash.empty() ? "" : hexstr(root_hash.data(), root_hash.size())) << "\",\n"
			          << "  \"files_checked\": " << files_checked << ",\n"
			          << "  \"files_passed\": " << files_passed << ",\n"
			          << "  \"files_failed\": " << files_failed << ",\n"
			          << "  \"verified_bytes\": " << total_bytes << ",\n"
			          << "  \"hash_records_checked\": " << total_hash_records << "\n"
			          << "}\n";
		}
		else
		{
			std::cout << "Integrity Check on Volume '" << vol->name() << "':\n"
			          << "  Sealed Volume (SSV): " << (vol->isSealed() ? "Yes" : "No") << "\n";
			if (has_im)
			{
				std::cout << "  Integrity Meta Ver : " << im.im_version << "\n"
				          << "  Seal Broken Flag   : " << ((im.im_flags & APFS_SEAL_BROKEN) ? "BROKEN" : "INTACT") << "\n"
				          << "  Root Hash          : " << hexstr(root_hash.data(), root_hash.size()) << "\n";
			}
			std::cout << "  Files Verified     : " << files_passed << " / " << files_checked << " (" << total_bytes << " bytes)\n"
			          << "  Data Hash Records  : " << total_hash_records << "\n"
			          << "  Result             : " << (files_failed == 0 ? "PASS" : "FAIL") << "\n";
		}
		device->Close();
		return files_failed == 0 ? 0 : 1;
	}

	// 12. BENCH command (Add-On #7 & Evaluation Benchmarks)
	if (cmd == "bench")
	{
		std::vector<WalkEntry> all;
		walk_tree_recursive(dir, ROOT_DIR_INO_NUM, "/", all);

		// 1. Cold pass (LRU cache disabled)
		ApfsDecompCache::Instance().SetEnabled(false);
		ApfsDecompCache::Instance().ResetStats();

		auto t0 = std::chrono::high_resolution_clock::now();
		uint64_t cold_bytes = 0;
		for (int iter = 0; iter < iterations; ++iter)
		{
			for (const auto &e : all)
			{
				if ((e.rec.mode & MODE_S_IFMT) == MODE_S_IFREG)
				{
					std::vector<uint8_t> buf;
					dir.ReadFileSmart(buf, e.ino, e.rec);
					cold_bytes += buf.size();
				}
			}
		}
		auto t1 = std::chrono::high_resolution_clock::now();
		double cold_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

		// 2. Warm pass (LRU cache enabled)
		ApfsDecompCache::Instance().SetEnabled(true);
		ApfsDecompCache::Instance().Clear();
		ApfsDecompCache::Instance().ResetStats();

		auto t2 = std::chrono::high_resolution_clock::now();
		uint64_t warm_bytes = 0;
		for (int iter = 0; iter < iterations; ++iter)
		{
			for (const auto &e : all)
			{
				if ((e.rec.mode & MODE_S_IFMT) == MODE_S_IFREG)
				{
					std::vector<uint8_t> buf;
					dir.ReadFileSmart(buf, e.ino, e.rec);
					warm_bytes += buf.size();
				}
			}
		}
		auto t3 = std::chrono::high_resolution_clock::now();
		double warm_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

		auto stats = ApfsDecompCache::Instance().GetStats();
		double speedup = (warm_ms > 0.0) ? (cold_ms / warm_ms) : 1.0;
		double cold_mbps = (cold_ms > 0.0) ? ((cold_bytes / (1024.0 * 1024.0)) / (cold_ms / 1000.0)) : 0.0;
		double warm_mbps = (warm_ms > 0.0) ? ((warm_bytes / (1024.0 * 1024.0)) / (warm_ms / 1000.0)) : 0.0;

		if (json_mode)
		{
			std::cout << std::fixed << std::setprecision(2)
			          << "{\n"
			          << "  \"iterations\": " << iterations << ",\n"
			          << "  \"total_entries\": " << all.size() << ",\n"
			          << "  \"bytes_read_per_pass\": " << (iterations > 0 ? warm_bytes / iterations : 0) << ",\n"
			          << "  \"cold_total_ms\": " << cold_ms << ",\n"
			          << "  \"warm_total_ms\": " << warm_ms << ",\n"
			          << "  \"cold_throughput_mb_s\": " << cold_mbps << ",\n"
			          << "  \"warm_throughput_mb_s\": " << warm_mbps << ",\n"
			          << "  \"speedup_x\": " << speedup << ",\n"
			          << "  \"cache_hits\": " << stats.hits << ",\n"
			          << "  \"cache_misses\": " << stats.misses << "\n"
			          << "}\n";
		}
		else
		{
			std::cout << std::fixed << std::setprecision(2)
			          << "APFS-Wonder Benchmark (" << iterations << " iterations across " << all.size() << " entries):\n"
			          << "  Uncached (Cold): " << cold_ms << " ms (" << cold_mbps << " MiB/s)\n"
			          << "  LRU Cached     : " << warm_ms << " ms (" << warm_mbps << " MiB/s)\n"
			          << "  Speedup        : " << speedup << "x (hits=" << stats.hits << ", misses=" << stats.misses << ")\n";
		}
		device->Close();
		return 0;
	}

	device->Close();
	return 0;
}
