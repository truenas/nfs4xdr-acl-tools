/*
 *  Copyright (c) 2021 iXsystems, Inc.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "libacl_nfs4.h"

static void
_print_diff_aces(struct nfs4_ace *a, struct nfs4_ace *b)
{
	if (a->type != b->type) {
		fprintf(stderr, "type: 0x%08x - 0x%08x ",
			a->type, b->type);
	}
	if (a->whotype != b->whotype) {
		fprintf(stderr, "whotype: 0x%08x - 0x%08x ",
			a->whotype, b->whotype);
	}
	if (a->whotype != b->whotype) {
		fprintf(stderr, "whotype: 0x%08x - 0x%08x ",
			a->whotype, b->whotype);
	}
	if (a->flag != b->flag) {
		fprintf(stderr, "flag: 0x%08x - 0x%08x ",
			a->flag, b->flag);
	}
	if (a->access_mask != b->access_mask) {
		fprintf(stderr, "access_mask: 0x%08x - 0x%08x ",
			a->access_mask, b->access_mask);
	}
	if (a->who_id != b->who_id) {
		fprintf(stderr, "who_id: %d - %d",
			a->who_id, b->who_id);
	}
	fprintf(stderr, "\n");
}

bool
ace_is_equal(struct nfs4_ace *entrya, struct nfs4_ace *entryb)
{
	if ((entrya->type != entryb->type) ||
	    (entrya->whotype != entryb->whotype) ||
	    (entrya->flag != entryb->flag) ||
	    (entrya->access_mask != entryb->access_mask) ||
	    (entrya->who_id != entryb->who_id)) {
#ifdef NFS4_DEBUG
		_print_diff_aces(entrya, entryb);
#endif
		return false;
	}
	return true;
}

/*
 * Compare two ACL structs and determine whether they are
 * equal.
 */
bool
aces_are_equal(struct nfs4_acl *a, struct nfs4_acl *b)
{
	struct nfs4_ace *entrya, *entryb;
	bool is_equal;

	if (a->naces != b->naces) {
#ifdef NFS4_DEBUG
		fprintf(stderr, "COUNT: %d - %d\n",
			a->naces, b->naces);
#endif
		return false;
	}

	for ((entrya = nfs4_get_first_ace(a)),
	     (entryb = nfs4_get_first_ace(b));
	     ((entrya != NULL) || (entryb != NULL));
	     (entrya = nfs4_get_next_ace(&entrya)),
	     ((entryb = nfs4_get_next_ace(&entryb)))) {
		is_equal = ace_is_equal(entrya, entryb);
		if (!is_equal) {
			return false;
		}
	}
	return true;
}

/*
 * This function populates the child ACL with entries inherited
 * from the parent ACL. is_dir refers to whether the target for
 * this ACL is a directory.
 *
 * Logic for this function is primarily derived from FreeBSD's
 * acl_nfs4_inherit_entries() from sys/kern/subr_acl_nfs4.c
 *
 * Primary difference is that all permissions may be inherited
 * and owner@, group@, everyone@ are not skipped. This is
 * consistent with ZFS behavior after aclmode property was
 * re-introduced. Ideally, we should get aclmode configuration
 * and use it to determine correct inherited ACLs.
 */
bool acl_nfs4_inherit_entries(struct nfs4_acl *parent_aclp,
			      struct nfs4_acl *child_aclp, bool is_dir)
{
	uint ret;
	nfs4_acl_flag_t flags;
	nfs4_acl_who_t tag;
	nfs4_acl_type_t type;
	nfs4_acl_perm_t a_mask;
	struct nfs4_ace *new_ace = NULL;
	struct nfs4_ace *ace = NULL;

	if (child_aclp == NULL) {
		return false;
	}

	for (ace = nfs4_get_first_ace(parent_aclp);
	     ace != NULL; ace = nfs4_get_next_ace(&ace)) {
		a_mask = ace->access_mask;
		flags = ace->flag;
		tag = ace->whotype;
		type = ace->type;

		/*
		 * Entry is not inheritable.
		 */
		if ((flags & (NFS4_ACE_FILE_INHERIT_ACE |
			NFS4_ACE_DIRECTORY_INHERIT_ACE)) == 0) {
			continue;
		}

		/*
		 * Creating a file, but entry does not have file
		 * inherit.
		 */
		if (!is_dir && ((flags & NFS4_ACE_FILE_INHERIT_ACE) == 0)) {
			continue;
		}

		/*
		 * Entry is inheritable only by files, but has NO_PROPAGATE
		 * flag set, and we're creating a directory so it wouldn't
		 * propagate.*
		 */
		if (is_dir && ((flags & NFS4_ACE_DIRECTORY_INHERIT_ACE) == 0) &&
		    (flags & NFS4_ACE_NO_PROPAGATE_INHERIT_ACE)) {
			continue;
		}

		/*
		 * Remove INHERIT_ONLY flag because it does not propagate
		 *
		 */
		flags &= ~NFS4_ACE_INHERIT_ONLY_ACE;

		/*
		 * Set INHERITED on newly-inherited ACEs
		 */
		flags |= NFS4_ACE_INHERITED_ACE;

		if ((type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) &&
		    (type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE)) {
			continue;
		}

		/*
		 * Remove inheritance flags in the following situations
		 * 1) NO_PROPAGATE_INHERIT - the ACE should not be inherited past
		 *    this directory.
		 * 2) This is a file - inheritance flags are invalid on files.
		 */
		if ((flags & NFS4_ACE_NO_PROPAGATE_INHERIT_ACE) || !is_dir) {
			flags &= ~(NFS4_ACE_NO_PROPAGATE_INHERIT_ACE |
				   NFS4_ACE_DIRECTORY_INHERIT_ACE |
				   NFS4_ACE_FILE_INHERIT_ACE |
				   NFS4_ACE_INHERIT_ONLY_ACE);
		}

		/*
		 * If this is a directory and FILE_INHERIT is set, ensure
		 * that INHERIT_ONLY is set. The result of this is that the
		 * ACE is not evaluated for access checks to this directory,
		 * but will be inherited by files created in the directory.
		 */
		if (is_dir && (flags & NFS4_ACE_FILE_INHERIT_ACE) &&
		    ((flags && NFS4_ACE_DIRECTORY_INHERIT_ACE) == 0)) {
			flags |= NFS4_ACE_INHERIT_ONLY_ACE;
		}
		new_ace = nfs4_new_ace(is_dir, type, flags, a_mask, tag, ace->who_id);
		if (new_ace == NULL) {
			return false;
		}
		ret = nfs4_append_ace(child_aclp, new_ace);
		if (ret != 0) {
			return false;
		}
	}
	return true;
}

/*
 * Calculate inherited ACL in a manner somewhat compatible with PSARC/2010/029. This
 * is also used to calculate a trivial ACL, by inheriting from a NULL ACL.
 * Logic primarily lifted from FreeBSD's subr_acl_nfs4.c. This sort of
 * function is inherently problematic because in userspace ACL info returned
 * from server lacks information about underlying aclmode configuration, which
 * would inform the correct inheritance behavior for a new ACL.
 */
bool acl_nfs4_calculate_inherited_acl(struct nfs4_acl *parent_aclp,
				      struct nfs4_acl *aclp,
				      mode_t mode, bool skip_mode,
				      int is_dir)
{
	nfs4_acl_perm_t user_allow_first = 0, user_deny = 0, group_deny = 0;
	nfs4_acl_perm_t user_allow, group_allow, everyone_allow;
	struct nfs4_ace *new_ace = NULL;
	bool ok;
	int ret;

	if ((aclp == NULL)) {
		errno = EINVAL;
		/* We lack a proper aclp */
		return false;
	}
	if ((parent_aclp == NULL) && skip_mode) {
		/* nothing to do */
		errno = EINVAL;
		return false;
	}

	user_allow = group_allow = everyone_allow = NFS4_ACE_BASE_ALLOW_PSARC;
	user_allow |= NFS4_ACE_USER_ALLOW_PSARC;
	if (mode & S_IRUSR) {
		user_allow |= NFS4_ACE_READ_DATA;
	}
	if (mode & S_IWUSR) {
		user_allow |= NFS4_ACE_POSIX_WRITE;
	}
	if (mode & S_IXUSR) {
		user_allow |= NFS4_ACE_EXECUTE;
	}
	if (mode & S_IRGRP) {
		group_allow |= NFS4_ACE_READ_DATA;
	}
	if (mode & S_IWGRP) {
		group_allow |= NFS4_ACE_POSIX_WRITE;
	}
	if (mode & S_IXGRP) {
		group_allow |= NFS4_ACE_EXECUTE;
	}
	if (mode & S_IROTH) {
		everyone_allow |= NFS4_ACE_READ_DATA;
	}
	if (mode & S_IWOTH) {
		everyone_allow |= NFS4_ACE_POSIX_WRITE;
	}
	if (mode & S_IXOTH) {
		everyone_allow |= NFS4_ACE_EXECUTE;
	}
	user_deny = ((group_allow | everyone_allow) & ~user_allow);
	group_deny = everyone_allow & ~group_allow;
	user_allow_first = group_deny & ~user_deny;
	if (!skip_mode) {
		if (user_allow_first != 0) {
			new_ace = nfs4_new_ace(
				is_dir, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
				0, user_allow_first, NFS4_ACL_WHO_OWNER, -1
			);
			if (new_ace == NULL) {
				return false;
			}
			ret = nfs4_append_ace(aclp, new_ace);
			if (ret != 0) {
				return false;
			}
		}
		if (user_deny != 0) {
			new_ace = nfs4_new_ace(
				is_dir, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				0, user_deny, NFS4_ACL_WHO_OWNER, -1
			);
			if (new_ace == NULL) {
				return false;
			}
			ret = nfs4_append_ace(aclp, new_ace);
			if (ret != 0) {
				return false;
			}
		}
		if (group_deny != 0) {
			new_ace = nfs4_new_ace(
				is_dir, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				NFS4_ACE_IDENTIFIER_GROUP,
				group_deny, NFS4_ACL_WHO_GROUP, -1
			);
			if (new_ace == NULL) {
				return false;
			}
			ret = nfs4_append_ace(aclp, new_ace);
			if (ret != 0) {
				return false;
			}
		}
	}
	if (parent_aclp != NULL) {
		ok = acl_nfs4_inherit_entries(parent_aclp, aclp, is_dir);
		if (!ok) {
			return false;
		}
	}
	if (!skip_mode) {
		new_ace = nfs4_new_ace(
			is_dir, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
			0, user_allow, NFS4_ACL_WHO_OWNER, -1
		);
		if (new_ace == NULL) {
			return false;
		}
		ret = nfs4_append_ace(aclp, new_ace);
		if (ret != 0) {
			return false;
		}
		new_ace = nfs4_new_ace(
			is_dir, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
			NFS4_ACE_IDENTIFIER_GROUP,
			group_allow, NFS4_ACL_WHO_GROUP, -1
		);
		if (new_ace == NULL) {
			return false;
		}
		ret = nfs4_append_ace(aclp, new_ace);
		if (ret != 0) {
			return false;
		}
		new_ace = nfs4_new_ace(
			is_dir, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
			0, everyone_allow, NFS4_ACL_WHO_EVERYONE, -1
		);
		if (new_ace == NULL) {
			return false;
		}
		ret = nfs4_append_ace(aclp, new_ace);
		if (ret != 0) {
			return false;
		}
	}
	return true;
}


/*
 * Evaluate owner@, group@, everyone@ entries and convert into a POSIX mode.
 */
bool acl_nfs4_sync_mode_from_acl(mode_t *_mode, struct nfs4_acl *aclp)
{
	mode_t old_mode = *_mode, mode = 0, deny_mode = 0;
	struct nfs4_ace *ace = NULL;

	for (ace = nfs4_get_first_ace(aclp); ace != NULL;
	     ace = nfs4_get_next_ace(&ace)) {
		if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE &&
		    ace->type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE) {
			fprintf(stderr, "Invalid ACE type: %d\n", ace->type);
			continue;
		}

                switch(ace->whotype) {
		case NFS4_ACL_WHO_OWNER:
#ifdef NFS4_DEBUG
			fprintf(stderr, "OWNER@: READ: %s, WRITE: %s, EXEC: %s type: 0x%08x\n",
				ace->access_mask & NFS4_ACE_READ_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_WRITE_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_EXECUTE ? "YES" : "NO",
				ace->type);
#endif

			if (ace->access_mask & NFS4_ACE_READ_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IRUSR;
				}
				else {
					deny_mode |= S_IRUSR;
				}
			}
			if (ace->access_mask & NFS4_ACE_WRITE_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IWUSR;
				}
				else {
					deny_mode |= S_IWUSR;
				}
			}
			if (ace->access_mask & NFS4_ACE_EXECUTE) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IXUSR;
				}
				else {
					deny_mode |= S_IXUSR;
				}
			}
                        break;
                case NFS4_ACL_WHO_GROUP:
#ifdef NFS4_DEBUG
			fprintf(stderr, "GROUP@: READ: %s, WRITE: %s, EXEC: %s, TYPE: 0x%08x\n",
				ace->access_mask & NFS4_ACE_READ_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_WRITE_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_EXECUTE ? "YES" : "NO",
				ace->type);
#endif

			if (ace->access_mask & NFS4_ACE_READ_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IRGRP;
				}
				else {
					deny_mode |= S_IRGRP;
				}
			}
			if (ace->access_mask & NFS4_ACE_WRITE_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IWGRP;
				}
				else {
					deny_mode |= S_IWGRP;
				}
			}
			if (ace->access_mask & NFS4_ACE_EXECUTE) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= S_IXGRP;
				}
				else {
					deny_mode |= S_IXGRP;
				}
			}
                        break;
                case NFS4_ACL_WHO_EVERYONE:
#ifdef NFS4_DEBUG
			fprintf(stderr, "EVERYONE@: READ: %s, WRITE: %s, EXEC: %s, TYPE: 0x%08x\n",
				ace->access_mask & NFS4_ACE_READ_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_WRITE_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_EXECUTE ? "YES" : "NO",
				ace->type);
#endif

			if (ace->access_mask & NFS4_ACE_READ_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= (S_IRUSR | S_IRGRP | S_IROTH);
				}
				else {
					deny_mode |= (S_IRUSR | S_IRGRP | S_IROTH);
				}
			}
			if (ace->access_mask & NFS4_ACE_WRITE_DATA) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= (S_IWUSR | S_IWGRP | S_IWOTH);
				}
				else {
					deny_mode |= (S_IWUSR | S_IWGRP | S_IWOTH);
				}
			}
			if (ace->access_mask & NFS4_ACE_EXECUTE) {
				if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
					mode |= (S_IXUSR | S_IXGRP | S_IXOTH);
				}
				else {
					deny_mode |= (S_IXUSR | S_IXGRP | S_IXOTH);
				}
			}
                        break;

		default:
#ifdef NFS4_DEBUG
			fprintf(stderr, "whotype: %d, who: %d: READ: %s, WRITE: %s, EXEC: %s\n",
				ace->whotype, ace->who_id,
				ace->access_mask & NFS4_ACE_READ_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_WRITE_DATA ? "YES" : "NO",
				ace->access_mask & NFS4_ACE_EXECUTE ? "YES" : "NO");
#endif
			break;

		}
	}
	mode &= ~deny_mode;
	*_mode = mode | old_mode;
#ifdef NFS4_DEBUG
	fprintf(stderr, "acl_nfs4_sync_mode_from_acl(): 0o%o\n", *_mode);
#endif
	return true;
}

/*
 * This function returns an nfs4_acl that is calculated by
 * converting the provided acl into one that can be expressed as a
 * POSIX mode without losing information. Logic is derived from
 * acl_strip_np(3) in FreeBSD and should be equivalent to results
 * from zfs_acl_chmod().
 *
 * Returned ACL must be freed.
 */
struct nfs4_acl *acl_nfs4_strip(struct nfs4_acl *acl)
{
	struct nfs4_acl *new_acl = NULL;
	mode_t calculated_mode = 0;
	bool ok;

	ok = acl_nfs4_sync_mode_from_acl(&calculated_mode, acl);
	if (!ok) {
		return NULL;
	}

	new_acl = nfs4_new_acl(acl->is_directory);
	if (new_acl == NULL) {
		return NULL;
	}

	ok = acl_nfs4_calculate_inherited_acl(NULL, new_acl,
					      calculated_mode, false,
					      acl->is_directory);
	if (!ok) {
		fprintf(stderr, "Failed to calculate_inherited_acl: %s\n",
			strerror(errno));
		nfs4_free_acl(new_acl);
		return NULL;
	}

	return new_acl;
}

/*
 * Determine whether the ACL can be expressed via POSIX permissions
 * without loss of information (is trivial). trivialp will be set to
 * 1 if the `acl` is trivial.
 *
 * This is accomplished by comparing a stripped copy of the ACL with
 * the original.
 */
int nfs4_acl_is_trivial_np(struct nfs4_acl *acl, int *trivialp)
{
	if (acl == NULL) {
		errno = EINVAL;
		return -1;
	}
	*trivialp = acl->aclflags4 & ACL_IS_TRIVIAL ? 1 : 0;
	return 0;
}
