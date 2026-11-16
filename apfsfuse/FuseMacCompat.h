/*
	This file is part of apfs-fuse, a read-only implementation of APFS
	(Apple File System) for FUSE.

	macOS FUSE compatibility layer supporting dynamic runtime loading of
	macFUSE (libfuse3 / libfuse.2), FUSE-T (libfuse-t), or OSXFUSE.
*/

#pragma once

#if defined(__APPLE__) && defined(APFS_FUSE_DYNAMIC_MACOS)

#include <cstddef>
#include <cstdint>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t fuse_ino_t;
typedef struct fuse_req *fuse_req_t;
struct fuse_session;
struct fuse_chan;

struct fuse_args {
	int argc;
	char **argv;
	int allocated;
};

#define FUSE_ARGS_INIT(argc, argv) { argc, argv, 0 }
#define FUSE_OPT_KEY_OPT -1
#define FUSE_OPT_KEY_NONOPT -2

struct fuse_opt {
	const char *templ;
	unsigned long offset;
	int value;
};

typedef int (*fuse_opt_proc_t)(void *data, const char *arg, int key, struct fuse_args *outargs);

struct fuse_file_info {
	int flags;
	unsigned int writepage : 1;
	unsigned int direct_io : 1;
	unsigned int keep_cache : 1;
	unsigned int flush : 1;
	unsigned int nonseekable : 1;
	unsigned int flock_release : 1;
	unsigned int cache_readdir : 1;
	unsigned int padding : 25;
	unsigned int padding2 : 32;
	uint64_t fh;
	uint64_t lock_owner;
	uint32_t poll_events;
};

struct fuse_entry_param {
	fuse_ino_t ino;
	uint64_t generation;
	struct stat attr;
	double attr_timeout;
	double entry_timeout;
};

struct fuse_lowlevel_ops {
	void (*init)(void *userdata, void *conn);
	void (*destroy)(void *userdata);
	void (*lookup)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*forget)(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
	void (*getattr)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*setattr)(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi);
	void (*readlink)(fuse_req_t req, fuse_ino_t ino);
	void (*mknod)(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
	void (*mkdir)(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
	void (*unlink)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*rmdir)(fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*symlink)(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);
	void (*rename)(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags);
	void (*link)(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname);
	void (*open)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*read)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
	void (*write)(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi);
	void (*flush)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*release)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*fsync)(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);
	void (*opendir)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*readdir)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
	void (*releasedir)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*fsyncdir)(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);
	void (*statfs)(fuse_req_t req, fuse_ino_t ino);
	void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags, uint32_t position);
	void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size, uint32_t position);
	void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);
	void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
};

int fuse_reply_err(fuse_req_t req, int err);
void fuse_reply_none(fuse_req_t req);
int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e);
int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double attr_timeout);
int fuse_reply_readlink(fuse_req_t req, const char *link);
int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi);
int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size);
int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf);
int fuse_reply_xattr(fuse_req_t req, size_t count);
size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize, const char *name, const struct stat *stbuf, off_t off);

int fuse_opt_add_arg(struct fuse_args *args, const char *arg);
int fuse_opt_parse(struct fuse_args *args, void *data, const struct fuse_opt opts[], fuse_opt_proc_t proc);
void fuse_opt_free_args(struct fuse_args *args);

struct fuse_session *fuse_session_new(struct fuse_args *args, const struct fuse_lowlevel_ops *op, size_t op_size, void *userdata);
int fuse_session_mount(struct fuse_session *se, const char *mountpoint);
int fuse_session_loop(struct fuse_session *se);
void fuse_session_unmount(struct fuse_session *se);
void fuse_session_destroy(struct fuse_session *se);

int fuse_set_signal_handlers(struct fuse_session *se);
void fuse_remove_signal_handlers(struct fuse_session *se);
int fuse_daemonize(int foreground);

#ifdef __cplusplus
}
#endif

#endif // defined(__APPLE__) && defined(APFS_FUSE_DYNAMIC_MACOS)
