/*-
 * Copyright 2020 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/xattr.h>
#include "libacl_nfs4.h"


#define	WA_NULL			0x00000000	/* nothing */
#define	WA_RECURSIVE		0x00000001	/* recursive */
#define	WA_VERBOSE		0x00000002	/* print more stuff */
#define	WA_CLONE		0x00000008	/* clone an ACL */
#define	WA_TRAVERSE		0x00000010	/* traverse filesystem mountpoints */
#define	WA_PHYSICAL		0x00000020	/* do not follow symlinks */
#define	WA_STRIP		0x00000040	/* strip ACL */
#define	WA_CHOWN		0x00000080	/* only chown */
#define	WA_TRIAL		0x00000100	/* trial run */
#define	WA_RESTORE		0x00000200	/* restore ACL */
#define	WA_FORCE		0x00000400	/* force */
#define	WA_INHERIT		0x00000800	/* do nfs41-style auto-inheritance */
#define	WA_POSIXACL		0x00001000	/* clone POSIXACL */
#define	WA_MAYCHMOD		0x00002000	/* strip POSIXACL and chmod */

#define	WA_OP_SET	(WA_CLONE|WA_STRIP|WA_CHOWN|WA_RESTORE|WA_INHERIT)
#define	WA_OP_CHECK(flags, bit) ((flags & ~bit) & WA_OP_SET)
#define IS_RECURSIVE(x) (x & WA_RECURSIVE)
#define IS_VERBOSE(x) (x & WA_VERBOSE)
#define IS_POSIXACL(x) (x & WA_POSIXACL)
#define MAY_CHMOD(x) (x & WA_MAYCHMOD)
#define MAY_XDEV(x) (x & WA_TRAVERSE)

#define	MAX_ACL_DEPTH		2

struct aclpair {
	struct nfs4_acl *dacl;
	struct nfs4_acl *facl;
};

struct aclpair theacls[MAX_ACL_DEPTH];

struct windows_acl_info {
	char *source;
	char *path;
	char *chroot;
	struct nfs4_acl *source_acl;
	dev_t root_dev;
	uid_t uid;
	gid_t gid;
	int	flags;
};

char *posixacl = NULL;
size_t posixacl_size = 0;
mode_t posixacl_mode = 0;

struct {
	const char *str;
	int action;
} actions[] = {
	{	"clone",	WA_CLONE	},
	{	"strip",	WA_STRIP	},
	{	"chown",	WA_CHOWN	},
	{	"inherit",	WA_INHERIT	},
	{	"restore",	WA_RESTORE	}
};

size_t actions_size = sizeof(actions) / sizeof(actions[0]);

static int
get_action(const char *str)
{
	int i;
	int action = WA_NULL;

	for (i = 0;i < actions_size;i++) {
		if (strcasecmp(actions[i].str, str) == 0) {
			action = actions[i].action;
			break;
		}
	}

	return action;
}

static struct windows_acl_info *
new_windows_acl_info(void)
{
	struct windows_acl_info *w = NULL;

	w = calloc(1, sizeof(struct windows_acl_info));
	if (w == NULL) {
		err(EX_OSERR, "calloc() failed");
	}

	w->uid = -1;
	w->gid = -1;
	return (w);
}


static void
free_windows_acl_info(struct windows_acl_info *w)
{
	if (w == NULL)
		return;

	free(w->path);
	free(w->chroot);
	nfs4_free_acl(w->source_acl);
	free(w);
}


static void
usage(char *path)
{
	if (strcmp(path, "cloneacl") == 0) {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -s <path>                    # source for ACL. If none specified then ACL taken from -p\n"
		"    -p <path>                    # path to recursively set ACL\n"
		"    -v                           # verbose\n",
		path
	);
	} else {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -a <clone|strip|chown|restore|inherit> # action to perform <restore> is experimental!\n"
		"    -O <owner>                     # change owner\n"
		"    -G <group>                     # change group\n"
		"    -c <path>                      # chroot path\n"
		"    -s <source>                    # source (if cloning ACL). If none specified then ACL taken from -p\n"
		"    -p <path>                      # path to set\n"
		"    -P                             # perform actions on POSIX1e ACL\n"
		"    -C                             # may strip and chmod() in POSIX1e ACL clone if no default ACL on path.\n"
		"    -r                             # recursive\n"
		"    -v                             # verbose\n"
		"    -t                             # trial run - makes no changes\n"
		"    -x                             # traverse filesystem mountpoints\n"
		"    -f                             # force acl inheritance\n",
		path
	);
	}

	exit(0);
}

static int
strip_acl(struct windows_acl_info *w, FTSENT *fts_entry)
{
	/*
	 * Convert non-trivial ACL to trivial ACL.
	 * This function is only called when action is set
	 * to 'strip'. A trivial ACL is one that is fully
	 * represented by the posix mode. If the goal is to
	 * simply remove ACLs, it will generally be more
	 * efficient to strip the ACL using setfacl -b
	 * from the root directory and then use the 'clone'
	 * action to set the ACL recursively.
	 */
	char *path = NULL;
	struct nfs4_acl *acl_tmp = NULL;
	struct nfs4_acl *acl_new = NULL;
	int error;

	if (fts_entry == NULL)
		path = w->path;
	else
		path = fts_entry->fts_accpath;

	if (IS_VERBOSE(w->flags))
		fprintf(stdout, "%s\n", path);
	acl_tmp = nfs4_acl_get_file(path);
	if (acl_tmp == NULL) {
		warn("%s: acl_get_file() failed", path);
		return (-1);
	}
	acl_new = acl_nfs4_strip(acl_tmp);
	if (acl_new == NULL) {
		warn("%s: acl_strip_np() failed", path);
		nfs4_free_acl(acl_tmp);
		return (-1);
	}

	error = nfs4_acl_set_file(acl_new, path);
	if (error) {
		warn("%s: acl_set_file() failed", path);
		nfs4_free_acl(acl_tmp);
		nfs4_free_acl(acl_new);
		return (-1);
	}
	nfs4_free_acl(acl_tmp);
	nfs4_free_acl(acl_new);

	if (w->uid != -1 || w->gid != -1) {
		error = chown(path, w->uid, w->gid);
		if (error) {
			warn("%s: chown() failed", path);
			return (-1);
		}
	}
	return (0);
}

static inline char *get_relative_path(FTSENT *entry, size_t plen)
{
	char *relpath = NULL;
	relpath = entry->fts_path + plen;
	if (relpath[0] == '/') {
		relpath++;
	}
	return relpath;
}

/*
 * Iterate through linked list of parent directories until we are able
 * to find one that exists in the snapshot directory. Use this ACL
 * to calculate an inherited acl.
 */
static int get_acl_parent(struct windows_acl_info *w, FTSENT *fts_entry)
{
	bool ok;
	FTSENT *p = NULL;
#if 0
	char *path = NULL;
	char *relpath = NULL;
#endif
	char shadow_path[PATH_MAX] = {0};
	struct nfs4_acl *parent_acl = NULL;

	if (fts_entry->fts_parent == NULL) {
		/*
		 * No parent node indicates we're at fts root level.
		 */
		parent_acl = nfs4_acl_get_file(w->source);
		if (parent_acl == NULL) {
			return (-1);
		}
		ok = acl_nfs4_inherit_entries(parent_acl, theacls[0].dacl, true);
		if (!ok) {
			warn("%s: acl_get_file() failed", w->source);
			return (-1);
		}
		ok = acl_nfs4_inherit_entries(parent_acl, theacls[0].facl, false);
		if (!ok) {
			warn("%s: acl_get_file() failed", w->source);
			return (-1);
		}
		nfs4_free_acl(parent_acl);
		return (0);
	}

	for (p=fts_entry->fts_parent; p; p=p->fts_parent) {
		snprintf(shadow_path, sizeof(shadow_path),
			  "%s/%s", w->source, p->fts_accpath);
		parent_acl = nfs4_acl_get_file(shadow_path);
		if (parent_acl == NULL) {
			if (errno == ENOENT) {
				continue;
			}
			else {
				warn("%s: acl_get_file() failed", shadow_path);
				return -1;

			}
		}

		ok = acl_nfs4_inherit_entries(parent_acl, theacls[0].dacl, true);
		if (!ok) {
			warn("%s: acl_get_file() failed", w->source);
			return (-1);
		}

		ok = acl_nfs4_inherit_entries(parent_acl, theacls[0].facl, false);
		if (ok) {
			nfs4_free_acl(parent_acl);
			return (0);
		}
		warn("%s: acl_get_file() failed", shadow_path);
		nfs4_free_acl(parent_acl);
	}
	return -1;
}

static int
restore_acl(struct windows_acl_info *w, char *relpath, FTSENT *fts_entry, size_t slen)
{
	int rval;
	bool is_equal;
	struct nfs4_acl *acl_new = NULL;
	struct nfs4_acl *acl_old = NULL;
	char shadow_path[PATH_MAX] = {0};

	if ((strlen(relpath) + strlen(w->source)) > PATH_MAX) {
		warn("%s: path in snapshot directory is too long", relpath);
		return -1;
	}

	rval = snprintf(shadow_path, sizeof(shadow_path), "%s/%s", w->source, relpath);
	if (rval < 0) {
		warn("%s: snprintf failed", relpath);
		return -1;
	}

	acl_new = nfs4_acl_get_file(shadow_path);
	if (acl_new == NULL) {
		if (errno == ENOENT) {
			if (w->flags & WA_FORCE) {
				rval = get_acl_parent(w, fts_entry);
				if (rval != 0) {
					fprintf(stdout, "! %s\n", shadow_path);
					return 0;
				}
				acl_new = acl_nfs4_copy_acl(((fts_entry->fts_statp->st_mode & S_IFDIR) == 0) ? theacls[0].facl : theacls[0].dacl);
				if (acl_new == NULL) {
					warn("%s: acl_dup() failed", shadow_path);
					return -1;
				}
			}
			else {
				fprintf(stdout, "! %s\n", shadow_path);
				return 0;
			}
		}
		else {
			warn("%s: acl_get_file() failed", shadow_path);
			return (-1);
		}
	}

	acl_old = nfs4_acl_get_file(fts_entry->fts_path);
	if (acl_old == NULL) {
		warn("%s: acl_get_file() failed", fts_entry->fts_path);
		return (-1);
	}

	is_equal = aces_are_equal(acl_new, acl_old);
	if (is_equal) {
		nfs4_free_acl(acl_old);
		nfs4_free_acl(acl_new);
		return 0;
	}

	if (IS_VERBOSE(w->flags)) {
		fprintf(stdout, "%s -> %s\n",
			shadow_path,
			fts_entry->fts_path);
	}
	if ((w->flags & WA_TRIAL) == 0) {
		rval = nfs4_acl_set_file(acl_new, fts_entry->fts_accpath);
		if (rval < 0) {
			warn("%s: acl_set_file() failed", fts_entry->fts_accpath);
			nfs4_free_acl(acl_old);
			nfs4_free_acl(acl_new);
			return -1;
		}
	}

	nfs4_free_acl(acl_old);
	nfs4_free_acl(acl_new);
	return 0;
}

static int
remove_acl_posix(struct windows_acl_info *w, FTSENT *file)
{
	int error;

	if (IS_VERBOSE(w->flags)) {
		fprintf(stdout, "%s\n", file->fts_path);
	}


	if (S_ISDIR(file->fts_statp->st_mode)) {
		error = removexattr(file->fts_accpath,
				    "system.posix_acl_default");
		if (error && errno != ENODATA) {
			warnx("%s: removexattr() for default ACL "
			      "failed: %s", file->fts_accpath, strerror(errno));
			return (error);
		}
	}

	error = removexattr(file->fts_accpath,
			    "system.posix_acl_access");
	if (error && errno != ENODATA) {
		warnx("%s: removexattr() for access ACL "
		      "failed: %s", file->fts_accpath, strerror(errno));
		return (error);
	}

	if (w->uid != -1 || w->gid != -1) {
		error = chown(file->fts_accpath, w->uid, w->gid);
		if (error) {
			warn("%s: chown() failed", file->fts_accpath);
			return (-1);
		}
	}

	return (error);
}

static int
set_acl_posix(struct windows_acl_info *w, FTSENT *file)
{
	size_t nwritten;
	int error;

	if (IS_VERBOSE(w->flags)) {
		fprintf(stdout, "%s\n", file->fts_path);
	}

	if (!posixacl && MAY_CHMOD(w->flags)) {
		error = remove_acl_posix(w, file);
		if (error) {
			return (error);
		}
		if ((file->fts_statp->st_mode & ALLPERMS) == posixacl_mode) {
			/* mode is already correct */
			return (0);
		}
		error = chmod(file->fts_accpath, posixacl_mode);
		if (error) {
			warnx("%s: chmod() to [0o%o] failed: %s\n",
			      file->fts_accpath, posixacl_mode,
			      strerror(errno));
			return (-1);
		}
		return (0);
	}

	if (S_ISDIR(file->fts_statp->st_mode)) {
		nwritten = setxattr(file->fts_accpath,
				    "system.posix_acl_default",
				    posixacl, posixacl_size, 0);

		if (nwritten == -1) {
			warnx("Failed to set default ACL on [%s]: %s\n",
			      file->fts_accpath, strerror(errno));
			return (-1);
		}
	}

	nwritten = setxattr(file->fts_accpath, "system.posix_acl_access",
			    posixacl, posixacl_size, 0);
	if (nwritten == -1) {
		warnx("Failed to set access ACL on [%s]: %s\n",
		      file->fts_accpath, strerror(errno));
		return (-1);
	}

	if (w->uid != -1 || w->gid != -1) {
		error = chown(file->fts_accpath, w->uid, w->gid);
		if (error) {
			warn("%s: chown() failed", file->fts_accpath);
			return (-1);
		}
	}
	return (0);
}

static int
set_acl(struct windows_acl_info *w, FTSENT *fts_entry)
{
	struct nfs4_acl *acl_new = NULL;
	int acl_depth = 0;

	if (IS_VERBOSE(w->flags)) {
		fprintf(stdout, "%s\n", fts_entry->fts_path);
	}

	/* don't set inherited flag on root dir. This is required for zfsacl:map_dacl_protected */
	if (fts_entry->fts_level == FTS_ROOTLEVEL) {
		acl_new = w->source_acl;
	}
	else {
		if ((fts_entry->fts_level -1) >= MAX_ACL_DEPTH) {
			acl_depth = MAX_ACL_DEPTH-1;
		}
		else {
			acl_depth = fts_entry->fts_level -1;
		}
		acl_new = ((fts_entry->fts_statp->st_mode & S_IFDIR) == 0) ? theacls[acl_depth].facl : theacls[acl_depth].dacl;
	}

	/* write out the acl to the file */
	if (nfs4_acl_set_file(acl_new, fts_entry->fts_accpath) < 0) {
		warn("%s: acl_set_file() failed", fts_entry->fts_accpath);
		return (-1);
	}

	if (w->uid != -1 || w->gid != -1) {
		if (chown(fts_entry->fts_accpath, w->uid, w->gid) < 0) {
			warn("%s: chown() failed", fts_entry->fts_accpath);
			return (-1);
		}
	}

	return (0);
}

static int
fts_compare(const FTSENT **s1, const FTSENT **s2)
{
	return (strcoll((*s1)->fts_name, (*s2)->fts_name));
}

static int
auto_inherit_acl(FTSENT *entry, struct nfs4_acl *cur_acl, int flags)
{
	struct nfs4_acl *new_acl = NULL;
	struct nfs4_acl *parent_acl = NULL;
	struct nfs4_acl *to_inherit = NULL;
	struct nfs4_ace *ace = NULL;
	struct nfs4_ace *new_ace = NULL;
	char parent[PATH_MAX] = {0};

	int is_dir, error;
	bool ok;

	if (entry->fts_parent == NULL) {
		warnx("fts_parent for [%s] is NULL\n", entry->fts_accpath);
		return (-1);
	}

	if (IS_VERBOSE(flags)) {
		fprintf(stdout, "%s\n", entry->fts_path);
	}

	is_dir = S_ISDIR(entry->fts_statp->st_mode);
	/*
	 * fts(3) will chdir into the parent directory of the current FTSENT
	 * unless FTS_NOCHDIR is set. Hence, retrieving parent directory is
	 * simply a matter of calling getcwd(3). This reliance on getcwd(3) is
	 * not symlink safe (it is possible for end-user to create to auto-
	 * inherit heads for the same path through symlink-following). At
	 * present this safety net is removed, but in the future a call to
	 * realpath(3) for file->fts_accpath may warranted in order to ensure
	 * that inherited ACL is always calculated based on the actual parent
	 * directory.
	 */
	if (getcwd(parent, sizeof(parent)) == NULL) {
		err(1, "%s: getcwd() failed.", entry->fts_accpath);
	}

	parent_acl = nfs4_acl_get_file(parent);
	if (parent_acl == NULL) {
		warnx("%s: nfs4_acl_get_file() failed.", parent);
		return (-1);
	}

	to_inherit = nfs4_new_acl(is_dir);
	if (to_inherit == NULL) {
		nfs4_free_acl(parent_acl);
		warnx("%s: nfs4_new_acl() failed.", entry->fts_accpath);
		return (-1);
	}

	/*
	 * Get inheritable entries from parent that we will use to replace
	 * our current inherited ones.
	 */
	ok = acl_nfs4_inherit_entries(parent_acl, to_inherit, is_dir);
	if (!ok) {
		nfs4_free_acl(parent_acl);
		nfs4_free_acl(to_inherit);
	}

	nfs4_free_acl(parent_acl);

	new_acl = nfs4_new_acl(is_dir);
	if (new_acl == NULL) {
		nfs4_free_acl(to_inherit);
		warnx("%s: nfs4_new_acl() failed.", entry->fts_accpath);
		return (-1);
	}

	/*
	 * First populate new ACL non-inherited entries from
	 * original ACL.
	 */
	for(ace = nfs4_get_first_ace(cur_acl); ace != NULL;
	    ace = nfs4_get_next_ace(&ace)) {
		/* Prune any inherited entries */
		if (ace->flag & NFS4_ACE_INHERITED_ACE) {
			continue;
		}
		new_ace = nfs4_new_ace(is_dir, ace->type, ace->flag,
				       ace->access_mask, ace->whotype,
				       ace->who_id);
		if (new_ace == NULL) {
			nfs4_free_acl(to_inherit);
			nfs4_free_acl(new_acl);
			warnx("%s: nfs4_new_ace() failed.",
			      entry->fts_accpath);
			return (-1);
		}

		error = nfs4_append_ace(new_acl, new_ace);
		if (error) {
			nfs4_free_acl(to_inherit);
			nfs4_free_acl(new_acl);
			warnx("%s: nfs4_append_ace() failed.",
			      entry->fts_accpath);
			return (-1);
		}
	}

	/*
	 * Now append inheritable entries from parent dir.
	 */
	for(ace = nfs4_get_first_ace(to_inherit); ace != NULL;
	    ace = nfs4_get_next_ace(&ace)) {
		new_ace = nfs4_new_ace(is_dir, ace->type, ace->flag,
				       ace->access_mask, ace->whotype,
				       ace->who_id);
		if (new_ace == NULL) {
			nfs4_free_acl(to_inherit);
			nfs4_free_acl(new_acl);
			warnx("%s: nfs4_new_ace() failed.",
			      entry->fts_accpath);
			return (-1);
		}

		error = nfs4_append_ace(new_acl, new_ace);
		if (error) {
			nfs4_free_acl(to_inherit);
			nfs4_free_acl(new_acl);
			warnx("%s: nfs4_append_ace() failed.",
			      entry->fts_accpath);
			return (-1);
		}
	}
	error = nfs4_acl_set_file(new_acl, entry->fts_path);
	if (error) {
		warnx("%s: nfs4_acl_set_file() failed.",
		      entry->fts_path);
	}
	return (error);
}

static int
do_action(struct windows_acl_info *w, FTS *ftsp, FTSENT *entry, int action)
{
	int rval;
	char *relpath = NULL;
	struct nfs4_acl *aclp = NULL;
	size_t slen, plen;

	switch(action){
	/*
	 * Restores ACL from source path.
	 */
	case WA_RESTORE:
		slen = strlen(w->source);
		plen = strlen(w->path);
		relpath = get_relative_path(entry, plen);

		if (strlen(entry->fts_path) > PATH_MAX) {
			warnx("%s: PATH TOO LONG", entry->fts_path);
			return -1;
		}
		rval = restore_acl(w, relpath, entry, slen);
		break;

	/*
	 * Trial run. Just prints out basic information about FTS tree.
	 */
	case WA_TRIAL:
		fprintf(stdout, "depth: %d, name: %s, full_path: %s\n",
			entry->fts_level, entry->fts_name, entry->fts_path);
		rval = 0;
		break;

	/*
	 * Convert ACL on file to be such that it is fully expressed by
	 * POSIX permissions.
	 */
	case WA_STRIP:
		rval = IS_POSIXACL(w->flags) ?
		       remove_acl_posix(w, entry) :
		       strip_acl(w, entry);
		if ((rval != 0) && (errno == EOPNOTSUPP) && MAY_XDEV(w->flags)) {
			rval = IS_POSIXACL(w->flags) ?
				strip_acl(w, entry) :
				remove_acl_posix(w, entry);
		}
		break;

	/*
	 * Legacy chown() that has advantage of not crossing (or changing) mountpoints.
	 */
	case WA_CHOWN:
		if ((w->uid == (uid_t)-1 || w->uid == entry->fts_statp->st_uid) &&
		    (w->gid == (gid_t)-1 || w->gid == entry->fts_statp->st_gid)){
			/* Nothing to do */
			rval = 0;
			break;
		}
		if (IS_VERBOSE(w->flags))
			fprintf(stdout, "%s\n", entry->fts_accpath);

		rval = chown(entry->fts_accpath, w->uid, w->gid);
		if (rval < 0) {
			warn("%s: chown() failed", entry->fts_accpath);
		}
		break;

	/*
	 * Generates inherited ACLs up to two levels deep and replaces existing
	 * entries with it (if recursive), non-recursive simply copies ACL from
	 * a -> b.
	 */
	case WA_CLONE:
		rval = IS_POSIXACL(w->flags) ?
		       set_acl_posix(w, entry) :
		       set_acl(w, entry);
		if ((rval != 0) && (errno == EOPNOTSUPP) && !IS_POSIXACL(w->flags)) {
			fts_set(ftsp, entry, FTS_SKIP);
			warnx("%s: path does not support NFSv4 ACLs. Skipping.",
			      entry->fts_path);
			rval = 0;
		}
		break;

	/*
	 * Performs ACL auto-inheritance
	 */
	case WA_INHERIT:
		if (IS_POSIXACL(w->flags)) {
			warnx("%s: NFSv41 auto-inheritance is not "
			      "possible for POSIX1E ACL type\n",
			      entry->fts_path);
			return (-1);
		}
		aclp = nfs4_acl_get_file(entry->fts_path);
		if (aclp == NULL) {
			warnx("%s: nfs4_acl_get_file() failed",
			      entry->fts_path);
			return (-1);
		}
		if (entry->fts_level == FTS_ROOTLEVEL){
			/*
			 * We set ACL_PROTECTED on rootlevel of
			 * our changes because we're de-facto breaking
			 * autoinheritance by triggering it from an arbitrary
			 * path.
			 */
			aclp->aclflags4 = ACL_PROTECTED;
			rval = nfs4_acl_set_file(aclp, entry->fts_path);
			if (rval) {
				warnx("%s: Failed to set PROTECTED on root",
				      entry->fts_path);
			}
			nfs4_free_acl(aclp);
			return rval;
		}
		/*
		 * If PROTECTED flag is set, we should skip this entry
		 * and prune from our FTS tree.
		 */
		if (aclp->aclflags4 & ACL_PROTECTED) {
			fts_set(ftsp, entry, FTS_SKIP);
			nfs4_free_acl(aclp);
			return (0);
		}
		rval = auto_inherit_acl(entry, aclp, w->flags);
		nfs4_free_acl(aclp);
		break;

	default:
		warnx("0x%08x: do_action() - unknown action", action);
		rval = -1;
	}

	return (rval);
}

static int
set_acls(struct windows_acl_info *w)
{
	FTS *tree = NULL;
	FTSENT *entry = NULL;
	int options = 0;
	char *paths[4];
	int rval;
	struct stat ftsroot_st;

	if (w == NULL)
		return (-1);

	if (stat(w->path, &ftsroot_st) < 0) {
		err(EX_OSERR, "%s: stat() failed", w->path);
	}

	paths[0] = w->path;
	paths[1] = NULL;

	if ((w->flags & WA_TRAVERSE) == 0 || (w->flags & WA_RESTORE)) {
		options |= FTS_XDEV;
	}

	if ((tree = fts_open(paths, options, fts_compare)) == NULL)
		err(EX_OSERR, "fts_open");

	/* traverse directory hierarchy */
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		if ((w->flags & WA_RECURSIVE) == 0) {
			if (entry->fts_level == FTS_ROOTLEVEL){
				rval = IS_POSIXACL(w->flags) ?
				       set_acl_posix(w, entry) :
				       set_acl(w, entry);
				break;
			}
		}

		/*
		 * Recursively set permissions for the target path.
		 * In case FTS_XDEV is set, we still need to check st_dev to avoid
		 * resetting permissions on subdatasets (FTS_XDEV will only prevent us
		 * from recursing into directories inside the subdataset.
		 */

		if ( (options & FTS_XDEV) && (ftsroot_st.st_dev != entry->fts_statp->st_dev) ){
			continue;
		}

		switch (entry->fts_info) {
		case FTS_D:
		case FTS_F:
			rval = do_action(w, tree, entry, (w->flags & WA_OP_SET));
			break;

		case FTS_ERR:
			warnx("%s: %s", entry->fts_path, strerror(entry->fts_errno));
			rval = -2;
			continue;
		}

		if (rval < 0) {
			err(EX_OSERR, "%s: set_acl() failed", entry->fts_accpath);
			continue;
		}

	}

	return (rval);
}


static void
usage_check(struct windows_acl_info *w)
{
	if (w->path == NULL)
		errx(EX_USAGE, "no path specified");

	if ((w->flags & WA_INHERIT) && !IS_RECURSIVE(w->flags)){
		errx(EX_USAGE, "inherit action requires recursive flag");
	}
	if (!WA_OP_CHECK(w->flags, ~WA_OP_SET) &&
		theacls[0].dacl == NULL && theacls[0].facl == NULL)
		errx(EX_USAGE, "nothing to do");

}

static int
copy_parent_entries(struct nfs4_acl *parent_acl, int level)
{
	theacls[level].dacl = acl_nfs4_copy_acl(parent_acl);
	if (theacls[level].dacl == NULL) {
		warnx("Failed to copy parent NFSv4 ACL");
		return (-1);
	}
	theacls[level].facl = acl_nfs4_copy_acl(parent_acl);
	if (theacls[level].facl == NULL) {
		warnx("Failed to copy parent NFSv4 ACL");
		return (-1);
	}
	return (0);
}

static int
calculate_inherited_acl(struct windows_acl_info *w, struct nfs4_acl *parent_acl, int level)
{
	bool ok;
	int error, trivial;
	struct nfs4_acl *d_acl = NULL;
	struct nfs4_acl *f_acl = NULL;
	d_acl = nfs4_new_acl(true);
	if (d_acl == NULL) {
		warnx("Failed to create new directory ACL.");
		return (-1);
	}
	error = nfs4_acl_is_trivial_np(parent_acl, &trivial);
	if (error) {
		warnx("acl_is_trivial() failed\n");
		return (-1);
	}
	if (trivial) {
		/* If Parent ACL is trivial, then simply copy it to child */
		return (copy_parent_entries(parent_acl, level));
	}

	ok = acl_nfs4_inherit_entries(parent_acl, d_acl, true);
	if (!ok) {
		nfs4_free_acl(d_acl);
		warnx("failed to get inherited entries\n");
		return (-1);
	}

	theacls[level].dacl = d_acl;
	f_acl = nfs4_new_acl(false);
	if (f_acl == NULL) {
		nfs4_free_acl(d_acl);
		warnx("Failed to create new file ACL.");
		return (-1);
	}

	ok = acl_nfs4_inherit_entries(parent_acl, f_acl, false);
	if (!ok) {
		warnx("Failed to generate inherited file ACL.");
		nfs4_free_acl(d_acl);
		nfs4_free_acl(f_acl);
		return (-1);
	}
	theacls[level].facl = f_acl;
	return 0;
}

static uid_t
id(const char *name, const char *type)
{
	uid_t val;
	char *ep = NULL;

	/*
	 * We know that uid_t's and gid_t's are unsigned longs.
	 */
	errno = 0;
	val = strtoul(name, &ep, 10);
	if (errno || *ep != '\0')
		errx(1, "%s: illegal %s name", name, type);
	return (val);
}

static gid_t
a_gid(const char *s)
{
	struct group *gr = NULL;
	return ((gr = getgrnam(s)) != NULL) ? gr->gr_gid : id(s, "group");
}

static uid_t
a_uid(const char *s)
{
	struct passwd *pw = NULL;
	return ((pw = getpwnam(s)) != NULL) ? pw->pw_uid : id(s, "user");
}

static char
*get_path(const char *p)
{
	char *out = NULL;
	out = realpath(p, NULL);
	return out;
}

static int
get_posix_acl(const char *path)
{
	int acl_size = 0;
	acl_size = getxattr(path, "system.posix_acl_default", NULL, 0);
	if (acl_size == -1) {
		return (-1);
	}
	posixacl = malloc(acl_size);
	if (posixacl == NULL) {
		errx(1, "malloc() failed");
	}
	posixacl_size = getxattr(path, "system.posix_acl_default",
				 posixacl, acl_size);
	if (posixacl_size == -1) {
		errx(1, "gextattr() failed to get default ACL.");
	}
	return (0);
}

static int
prepare_clone(struct windows_acl_info *w)
{
	int error;
	struct stat st;
	struct nfs4_acl	*source_acl = NULL;
	warnx("flags: 0x%08x\n", w->flags);
	if (IS_POSIXACL(w->flags)) {
		error = get_posix_acl(w->source);
		if (error & MAY_CHMOD(w->flags)) {
			error = stat(w->source, &st);
			if (error) {
				errx(1, "%s: stat() failed. Unable "
				     "to prepare clone action",
				     w->source);
			}
			posixacl_mode = (st.st_mode & ALLPERMS);
		}
		else if (error) {
			warnx("%s: No default ACL present on file. "
			      "Nothing to inherit.", w->source);
			return (-1);
		}
		return (0);
	}
	source_acl = nfs4_acl_get_file(w->source);
	if (source_acl == NULL) {
		warnx("%s: acl_get_file() failed: %s",
		      w->source, strerror(errno));
		return (-1);
	}

	w->source_acl = acl_nfs4_copy_acl(source_acl);
	if (calculate_inherited_acl(w, w->source_acl, 0) != 0) {
		free_windows_acl_info(w);
		return (-1);
	}
	if (calculate_inherited_acl(w, theacls[0].dacl, 1) != 0) {
		free_windows_acl_info(w);
		return (-1);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	int 	ch, ret, error;
	struct 	windows_acl_info *w = NULL;
	ch = ret = 0;
	struct stat st;

	if (argc < 2) {
		usage(argv[0]);
	}

	w = new_windows_acl_info();
	while ((ch = getopt(argc, argv, "a:O:G:c:s:p:CPrftvx")) != -1) {
		switch (ch) {
			case 'a': {
				int action = get_action(optarg);
				if (action == WA_NULL)
					errx(EX_USAGE, "invalid action");
				if (WA_OP_CHECK(w->flags, action))
					errx(EX_USAGE, "only one action can be specified");
				w->flags |= action;
				break;
			}

			case 'O': {
				w->uid = a_uid(optarg);
				break;
			}

			case 'G': {
				w->gid = a_gid(optarg);
				break;
			}

			case 'c':
				w->chroot = get_path(optarg);
				break;

			case 's':
				w->source = get_path(optarg);
				break;

			case 'p':
				w->path = get_path(optarg);
				break;

			case 'P':
				w->flags |= WA_POSIXACL;
				break;

			case 'C':
				w->flags |= WA_MAYCHMOD;
				break;

			case 'r':
				w->flags |= WA_RECURSIVE;
				break;

			case 't':
				w->flags |= WA_TRIAL;
				break;

			case 'v':
				w->flags |= WA_VERBOSE;
				break;

			case 'x':
				w->flags |= WA_TRAVERSE;
				break;

			case 'f':
				w->flags |= WA_FORCE;
				break;

			case '?':
			default:
				usage(argv[0]);
			}
	}

	/* set the source to the destination if we lack -s */
	if (w->source == NULL) {
		if (w->flags & WA_RESTORE) {
			warn("source must be set for restore jobs");
			return (1);
		}
		w->source = w->path;
	}
	if (stat("/", &st) < 0) {
		warn("%s: stat() failed.", "/");
		return (1);
	}
	w->root_dev = st.st_dev;

	if (w->chroot != NULL) {
		if (w->source != NULL) {
			if (strncmp(w->chroot, w->source, strlen(w->chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w->source);
				free_windows_acl_info(w);
				return (1);
			}
			if (strlen(w->chroot) == strlen(w->source)) {
				w->source = strdup(".");
			}
			else {
				w->source += strlen(w->chroot);
			}
		}
		if (w->path != NULL ) {
			if (strncmp(w->chroot, w->path, strlen(w->chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w->path);
				free_windows_acl_info(w);
				return (1);
			}
			if (strlen(w->chroot) == strlen(w->path)) {
				w->path = strdup(".");
			}
			else {
				w->path += strlen(w->chroot);
			}
		}
		ret = chdir(w->chroot);
		if (ret == -1) {
			warn("%s: chdir() failed.", w->chroot);
			free_windows_acl_info(w);
			return (1);
		}
		ret = chroot(w->chroot);
		if (ret == -1) {
			warn("%s: chroot() failed.", w->chroot);
			free_windows_acl_info(w);
			return (1);
		}
		if (access(w->path, F_OK) < 0) {
			warn("%s: access() failed after chroot.", w->path);
			free_windows_acl_info(w);
			return (1);
		}
	}

	if (access(w->source, F_OK) < 0) {
		warn("%s: access() failed.", w->source);
		free_windows_acl_info(w);
		return (1);
	}

	if (w->flags & WA_CLONE){
		error = prepare_clone(w);
		if (error) {
			free_windows_acl_info(w);
			return (1);
		}
	}

	usage_check(w);


	if (set_acls(w) <0) {
		ret = 1;
	}

	free_windows_acl_info(w);
	return (ret);
}
