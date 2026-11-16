/*
	This file is part of apfs-fuse, a read-only implementation of APFS
	(Apple File System) for FUSE.

	macOS FUSE compatibility layer supporting dynamic runtime loading of
	macFUSE (libfuse3 / libfuse.2), FUSE-T (libfuse-t), or OSXFUSE.
*/

#if defined(__APPLE__) && defined(APFS_FUSE_DYNAMIC_MACOS)

#include "FuseMacCompat.h"

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

// FUSE 2 file_info layout on macOS (macFUSE / FUSE-T / OSXFUSE)
struct fuse2_file_info {
	int flags;
	unsigned long fh_old;
	int writepage;
	unsigned int direct_io : 1;
	unsigned int keep_cache : 1;
	unsigned int flush : 1;
	unsigned int nonseekable : 1;
	unsigned int flock_release : 1;
	unsigned int purge_attr : 1;
	unsigned int purge_ubc : 1;
	unsigned int padding : 25;
	uint64_t fh;
	uint64_t lock_owner;
};

// FUSE 2 lowlevel_ops layout on macOS (macFUSE / FUSE-T / OSXFUSE)
struct fuse2_lowlevel_ops {
	void (*init)(void *userdata, void *conn);
	void (*destroy)(void *userdata);
	void (*lookup)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*forget)(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
	void (*getattr)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*setattr)(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse2_file_info *fi);
	void (*readlink)(fuse_req_t req, fuse_ino_t ino);
	void (*mknod)(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
	void (*mkdir)(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
	void (*unlink)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*rmdir)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*symlink)(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);
	void (*rename)(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname);
	void (*link)(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname);
	void (*open)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*read)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse2_file_info *fi);
	void (*write)(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse2_file_info *fi);
	void (*flush)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*release)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*fsync)(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse2_file_info *fi);
	void (*opendir)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*readdir)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse2_file_info *fi);
	void (*releasedir)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi);
	void (*fsyncdir)(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse2_file_info *fi);
	void (*statfs)(fuse_req_t req, fuse_ino_t ino);
	void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags, uint32_t position);
	void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size, uint32_t position);
	void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);
	void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
	void (*access)(fuse_req_t req, fuse_ino_t ino, int mask);
	void (*create)(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse2_file_info *fi);
	void (*getlk)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi, struct flock *lock);
	void (*setlk)(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi, struct flock *lock, int sleep);
	void (*bmap)(fuse_req_t req, fuse_ino_t ino, size_t blocksize, uint64_t idx);
	void *padding[16];
};

struct DynFuse {
	void *handle = nullptr;
	bool is_fuse3 = false;

	// Common symbols
	int (*reply_err)(fuse_req_t, int) = nullptr;
	void (*reply_none)(fuse_req_t) = nullptr;
	int (*reply_entry)(fuse_req_t, const struct fuse_entry_param *) = nullptr;
	int (*reply_attr)(fuse_req_t, const struct stat *, double) = nullptr;
	int (*reply_readlink)(fuse_req_t, const char *) = nullptr;
	int (*reply_open)(fuse_req_t, const void *) = nullptr;
	int (*reply_buf)(fuse_req_t, const char *, size_t) = nullptr;
	int (*reply_statfs)(fuse_req_t, const struct statvfs *) = nullptr;
	int (*reply_xattr)(fuse_req_t, size_t) = nullptr;
	size_t (*add_direntry)(fuse_req_t, char *, size_t, const char *, const struct stat *, off_t) = nullptr;

	int (*set_signal_handlers)(struct fuse_session *) = nullptr;
	void (*remove_signal_handlers)(struct fuse_session *) = nullptr;
	int (*daemonize)(int) = nullptr;
	int (*session_loop)(struct fuse_session *) = nullptr;
	void (*session_destroy)(struct fuse_session *) = nullptr;

	// FUSE 3 symbols
	struct fuse_session *(*session_new)(struct fuse_args *, const void *, size_t, void *) = nullptr;
	int (*session_mount)(struct fuse_session *, const char *) = nullptr;
	void (*session_unmount)(struct fuse_session *) = nullptr;

	// FUSE 2 symbols
	struct fuse_chan *(*mount_v2)(const char *, struct fuse_args *) = nullptr;
	struct fuse_session *(*lowlevel_new_v2)(struct fuse_args *, const void *, size_t, void *) = nullptr;
	void (*session_add_chan_v2)(struct fuse_session *, struct fuse_chan *) = nullptr;
	void (*session_remove_chan_v2)(struct fuse_chan *) = nullptr;
	void (*unmount_v2)(const char *, struct fuse_chan *) = nullptr;

	// Saved state for FUSE 2 bridging
	struct fuse_args saved_args = FUSE_ARGS_INIT(0, nullptr);
	struct fuse_lowlevel_ops user_ops = {};
	struct fuse2_lowlevel_ops bridged_ops2 = {};
	struct fuse_chan *chan_v2 = nullptr;
	std::string mountpoint_v2;
	fuse2_file_info *active_fi2 = nullptr;
};

static DynFuse g_fuse;

static void bridge_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.user_ops.getattr(req, ino, fi2 ? &fi3 : nullptr);
}

static void bridge_open(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.active_fi2 = fi2;
	g_fuse.user_ops.open(req, ino, &fi3);
	g_fuse.active_fi2 = nullptr;
}

static void bridge_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.active_fi2 = fi2;
	g_fuse.user_ops.opendir(req, ino, &fi3);
	g_fuse.active_fi2 = nullptr;
}

static void bridge_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.user_ops.read(req, ino, size, off, &fi3);
}

static void bridge_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.user_ops.readdir(req, ino, size, off, &fi3);
}

static void bridge_release(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.user_ops.release(req, ino, &fi3);
}

static void bridge_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse2_file_info *fi2)
{
	struct fuse_file_info fi3 = {};
	if (fi2) {
		fi3.flags = fi2->flags;
		fi3.fh = fi2->fh;
	}
	g_fuse.user_ops.releasedir(req, ino, &fi3);
}

static bool load_fuse_library()
{
	if (g_fuse.handle)
		return true;

	static const char *fuse3_candidates[] = {
		"/usr/local/lib/libfuse3.dylib",
		"/opt/homebrew/lib/libfuse3.dylib",
		"libfuse3.dylib",
		nullptr
	};

	static const char *fuse2_candidates[] = {
		"/usr/local/lib/libfuse.2.dylib",
		"/usr/local/lib/libfuse.dylib",
		"/opt/homebrew/lib/libfuse.2.dylib",
		"/opt/homebrew/lib/libfuse.dylib",
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Application Support/fuse-t/lib/libfuse-t.dylib",
		"/usr/local/lib/libosxfuse.2.dylib",
		"/usr/local/lib/libosxfuse.dylib",
		"libfuse.2.dylib",
		"libfuse-t.dylib",
		nullptr
	};

	for (int i = 0; fuse3_candidates[i]; ++i) {
		void *h = dlopen(fuse3_candidates[i], RTLD_NOW | RTLD_LOCAL);
		if (h && dlsym(h, "fuse_session_new")) {
			g_fuse.handle = h;
			g_fuse.is_fuse3 = true;
			break;
		}
		if (h)
			dlclose(h);
	}

	if (!g_fuse.handle) {
		for (int i = 0; fuse2_candidates[i]; ++i) {
			void *h = dlopen(fuse2_candidates[i], RTLD_NOW | RTLD_LOCAL);
			if (h && dlsym(h, "fuse_lowlevel_new")) {
				g_fuse.handle = h;
				g_fuse.is_fuse3 = false;
				break;
			}
			if (h)
				dlclose(h);
		}
	}

	if (!g_fuse.handle) {
		std::cerr << "Error: No macOS FUSE runtime library found (checked macFUSE libfuse3/libfuse and FUSE-T)." << std::endl;
		std::cerr << "Install macFUSE (https://macfuse.github.io / 'brew install --cask macfuse') or FUSE-T ('brew install --cask fuse-t')." << std::endl;
		return false;
	}

	g_fuse.reply_err = reinterpret_cast<decltype(g_fuse.reply_err)>(dlsym(g_fuse.handle, "fuse_reply_err"));
	g_fuse.reply_none = reinterpret_cast<decltype(g_fuse.reply_none)>(dlsym(g_fuse.handle, "fuse_reply_none"));
	g_fuse.reply_entry = reinterpret_cast<decltype(g_fuse.reply_entry)>(dlsym(g_fuse.handle, "fuse_reply_entry"));
	g_fuse.reply_attr = reinterpret_cast<decltype(g_fuse.reply_attr)>(dlsym(g_fuse.handle, "fuse_reply_attr"));
	g_fuse.reply_readlink = reinterpret_cast<decltype(g_fuse.reply_readlink)>(dlsym(g_fuse.handle, "fuse_reply_readlink"));
	g_fuse.reply_open = reinterpret_cast<decltype(g_fuse.reply_open)>(dlsym(g_fuse.handle, "fuse_reply_open"));
	g_fuse.reply_buf = reinterpret_cast<decltype(g_fuse.reply_buf)>(dlsym(g_fuse.handle, "fuse_reply_buf"));
	g_fuse.reply_statfs = reinterpret_cast<decltype(g_fuse.reply_statfs)>(dlsym(g_fuse.handle, "fuse_reply_statfs"));
	g_fuse.reply_xattr = reinterpret_cast<decltype(g_fuse.reply_xattr)>(dlsym(g_fuse.handle, "fuse_reply_xattr"));
	g_fuse.add_direntry = reinterpret_cast<decltype(g_fuse.add_direntry)>(dlsym(g_fuse.handle, "fuse_add_direntry"));

	g_fuse.set_signal_handlers = reinterpret_cast<decltype(g_fuse.set_signal_handlers)>(dlsym(g_fuse.handle, "fuse_set_signal_handlers"));
	g_fuse.remove_signal_handlers = reinterpret_cast<decltype(g_fuse.remove_signal_handlers)>(dlsym(g_fuse.handle, "fuse_remove_signal_handlers"));
	g_fuse.daemonize = reinterpret_cast<decltype(g_fuse.daemonize)>(dlsym(g_fuse.handle, "fuse_daemonize"));
	g_fuse.session_loop = reinterpret_cast<decltype(g_fuse.session_loop)>(dlsym(g_fuse.handle, "fuse_session_loop"));
	g_fuse.session_destroy = reinterpret_cast<decltype(g_fuse.session_destroy)>(dlsym(g_fuse.handle, "fuse_session_destroy"));

	if (g_fuse.is_fuse3) {
		g_fuse.session_new = reinterpret_cast<decltype(g_fuse.session_new)>(dlsym(g_fuse.handle, "fuse_session_new"));
		g_fuse.session_mount = reinterpret_cast<decltype(g_fuse.session_mount)>(dlsym(g_fuse.handle, "fuse_session_mount"));
		g_fuse.session_unmount = reinterpret_cast<decltype(g_fuse.session_unmount)>(dlsym(g_fuse.handle, "fuse_session_unmount"));
	} else {
		g_fuse.mount_v2 = reinterpret_cast<decltype(g_fuse.mount_v2)>(dlsym(g_fuse.handle, "fuse_mount"));
		g_fuse.lowlevel_new_v2 = reinterpret_cast<decltype(g_fuse.lowlevel_new_v2)>(dlsym(g_fuse.handle, "fuse_lowlevel_new"));
		g_fuse.session_add_chan_v2 = reinterpret_cast<decltype(g_fuse.session_add_chan_v2)>(dlsym(g_fuse.handle, "fuse_session_add_chan"));
		g_fuse.session_remove_chan_v2 = reinterpret_cast<decltype(g_fuse.session_remove_chan_v2)>(dlsym(g_fuse.handle, "fuse_session_remove_chan"));
		g_fuse.unmount_v2 = reinterpret_cast<decltype(g_fuse.unmount_v2)>(dlsym(g_fuse.handle, "fuse_unmount"));
	}

	return true;
}

} // namespace

extern "C" {

int fuse_opt_add_arg(struct fuse_args *args, const char *arg)
{
	if (!args || !arg)
		return -1;

	char **new_argv = static_cast<char **>(std::realloc(args->allocated ? args->argv : nullptr, sizeof(char *) * (args->argc + 2)));
	if (!new_argv)
		return -1;

	if (!args->allocated && args->argc > 0 && args->argv) {
		for (int i = 0; i < args->argc; ++i)
			new_argv[i] = strdup(args->argv[i]);
	}

	args->argv = new_argv;
	args->allocated = 1;
	args->argv[args->argc] = strdup(arg);
	args->argc++;
	args->argv[args->argc] = nullptr;
	return 0;
}

int fuse_opt_parse(struct fuse_args *args, void *data, const struct fuse_opt opts[], fuse_opt_proc_t proc)
{
	(void)opts;
	if (!args || !proc)
		return 0;

	std::vector<std::string> kept_args;
	for (int i = 0; i < args->argc; ++i) {
		const char *a = args->argv[i];
		if (std::strcmp(a, "-o") == 0 && (i + 1) < args->argc) {
			++i;
			std::string optlist = args->argv[i];
			std::stringstream ss(optlist);
			std::string item;
			std::string remaining;
			while (std::getline(ss, item, ',')) {
				int res = proc(data, item.c_str(), FUSE_OPT_KEY_OPT, args);
				if (res == 1) {
					if (!remaining.empty())
						remaining.push_back(',');
					remaining.append(item);
				} else if (res < 0) {
					return -1;
				}
			}
			if (!remaining.empty()) {
				kept_args.push_back("-o");
				kept_args.push_back(remaining);
			}
		} else {
			kept_args.push_back(a);
		}
	}

	fuse_opt_free_args(args);
	for (const auto &s : kept_args)
		fuse_opt_add_arg(args, s.c_str());

	return 0;
}

void fuse_opt_free_args(struct fuse_args *args)
{
	if (!args)
		return;
	if (args->argv && args->allocated) {
		for (int i = 0; i < args->argc; ++i)
			std::free(args->argv[i]);
		std::free(args->argv);
	}
	args->argv = nullptr;
	args->argc = 0;
	args->allocated = 0;
}

int fuse_reply_err(fuse_req_t req, int err)
{
	return g_fuse.reply_err ? g_fuse.reply_err(req, err) : -1;
}

void fuse_reply_none(fuse_req_t req)
{
	if (g_fuse.reply_none)
		g_fuse.reply_none(req);
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
	return g_fuse.reply_entry ? g_fuse.reply_entry(req, e) : -1;
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double attr_timeout)
{
	return g_fuse.reply_attr ? g_fuse.reply_attr(req, attr, attr_timeout) : -1;
}

int fuse_reply_readlink(fuse_req_t req, const char *link)
{
	return g_fuse.reply_readlink ? g_fuse.reply_readlink(req, link) : -1;
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi)
{
	if (!g_fuse.reply_open)
		return -1;
	if (!g_fuse.is_fuse3 && g_fuse.active_fi2 && fi) {
		g_fuse.active_fi2->fh = fi->fh;
		return g_fuse.reply_open(req, g_fuse.active_fi2);
	}
	return g_fuse.reply_open(req, fi);
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
	return g_fuse.reply_buf ? g_fuse.reply_buf(req, buf, size) : -1;
}

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf)
{
	return g_fuse.reply_statfs ? g_fuse.reply_statfs(req, stbuf) : -1;
}

int fuse_reply_xattr(fuse_req_t req, size_t count)
{
	return g_fuse.reply_xattr ? g_fuse.reply_xattr(req, count) : -1;
}

size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize, const char *name, const struct stat *stbuf, off_t off)
{
	return g_fuse.add_direntry ? g_fuse.add_direntry(req, buf, bufsize, name, stbuf, off) : 0;
}

struct fuse_session *fuse_session_new(struct fuse_args *args, const struct fuse_lowlevel_ops *op, size_t op_size, void *userdata)
{
	if (!load_fuse_library())
		return nullptr;

	if (g_fuse.is_fuse3)
		return g_fuse.session_new(args, op, op_size, userdata);

	// Bridge FUSE 3 session setup to FUSE 2
	g_fuse.user_ops = *op;
	std::memset(&g_fuse.bridged_ops2, 0, sizeof(g_fuse.bridged_ops2));
	g_fuse.bridged_ops2.lookup = op->lookup;
	g_fuse.bridged_ops2.getattr = op->getattr ? bridge_getattr : nullptr;
	g_fuse.bridged_ops2.readlink = op->readlink;
	g_fuse.bridged_ops2.open = op->open ? bridge_open : nullptr;
	g_fuse.bridged_ops2.read = op->read ? bridge_read : nullptr;
	g_fuse.bridged_ops2.release = op->release ? bridge_release : nullptr;
	g_fuse.bridged_ops2.opendir = op->opendir ? bridge_opendir : nullptr;
	g_fuse.bridged_ops2.readdir = op->readdir ? bridge_readdir : nullptr;
	g_fuse.bridged_ops2.releasedir = op->releasedir ? bridge_releasedir : nullptr;
	g_fuse.bridged_ops2.statfs = op->statfs;
	g_fuse.bridged_ops2.getxattr = op->getxattr;
	g_fuse.bridged_ops2.listxattr = op->listxattr;

	fuse_opt_free_args(&g_fuse.saved_args);
	for (int i = 0; i < args->argc; ++i)
		fuse_opt_add_arg(&g_fuse.saved_args, args->argv[i]);

	return g_fuse.lowlevel_new_v2(args, &g_fuse.bridged_ops2, sizeof(g_fuse.bridged_ops2), userdata);
}

int fuse_session_mount(struct fuse_session *se, const char *mountpoint)
{
	if (g_fuse.is_fuse3)
		return g_fuse.session_mount ? g_fuse.session_mount(se, mountpoint) : -1;

	if (!g_fuse.mount_v2 || !g_fuse.session_add_chan_v2)
		return -1;

	g_fuse.chan_v2 = g_fuse.mount_v2(mountpoint, &g_fuse.saved_args);
	if (!g_fuse.chan_v2)
		return -1;

	g_fuse.mountpoint_v2 = mountpoint ? mountpoint : "";
	g_fuse.session_add_chan_v2(se, g_fuse.chan_v2);
	return 0;
}

int fuse_session_loop(struct fuse_session *se)
{
	return g_fuse.session_loop ? g_fuse.session_loop(se) : -1;
}

void fuse_session_unmount(struct fuse_session *se)
{
	if (g_fuse.is_fuse3) {
		if (g_fuse.session_unmount)
			g_fuse.session_unmount(se);
		return;
	}

	if (g_fuse.chan_v2) {
		if (g_fuse.session_remove_chan_v2)
			g_fuse.session_remove_chan_v2(g_fuse.chan_v2);
		if (g_fuse.unmount_v2)
			g_fuse.unmount_v2(g_fuse.mountpoint_v2.c_str(), g_fuse.chan_v2);
		g_fuse.chan_v2 = nullptr;
	}
}

void fuse_session_destroy(struct fuse_session *se)
{
	if (g_fuse.session_destroy)
		g_fuse.session_destroy(se);
	fuse_opt_free_args(&g_fuse.saved_args);
}

int fuse_set_signal_handlers(struct fuse_session *se)
{
	return g_fuse.set_signal_handlers ? g_fuse.set_signal_handlers(se) : 0;
}

void fuse_remove_signal_handlers(struct fuse_session *se)
{
	if (g_fuse.remove_signal_handlers)
		g_fuse.remove_signal_handlers(se);
}

int fuse_daemonize(int foreground)
{
	return g_fuse.daemonize ? g_fuse.daemonize(foreground) : 0;
}

} // extern "C"

#endif // defined(__APPLE__) && defined(APFS_FUSE_DYNAMIC_MACOS)
