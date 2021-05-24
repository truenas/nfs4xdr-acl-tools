/*  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
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


#ifndef LIBACL_NFS4_H
#define LIBACL_NFS4_H 1

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/errno.h>
#include <string.h>
#include <stdbool.h>
#include <jansson.h>
#include <bsd/string.h>
#include "nfs4.h"

#define ACL_TEXT_NUMERIC_IDS		0x0000001
#define ACL_TEXT_VERBOSE		0x0000002
#define ACL_TEXT_APPEND_ID		0x0000004

#if 0 /* see comment in nfs4_new_ace.c */
/* flags used to simulate posix default ACLs */
#define NFS4_ACE_MASK_IGNORE (NFS4_ACE_DELETE | NFS4_ACE_WRITE_OWNER \
		| NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_WRITE_NAMED_ATTRS)
#endif

/*
 * NFS4_MAX_ACESIZE -- the number of bytes in the string representation we
 * read in (not the same as on-the-wire, which is also not the same as how
 * NFSD actually stores the ACEs).
 *
 * Note that right now NFSD tolerates at most 170 ACEs, regardless of size,
 * and linux in general tolerates at most 64KB xattrs.
 *
 * :     3 of these
 * type  1
 * flag  7 (total number of flag characters)
 * who   NFS4_MAX_PRINCIPALSIZE  (user:128, domain:256, '@':1, NULL:1)
 * mask  14 (total number of dir + common mask characters)
 *
 * which equals 410.  let's try that for now.
 */
/* Fixme: this is used for buffer size when reading ACEs from spec file */
#define NFS4_MAX_ACESIZE	(3 + 1 + 7 + NFS4_MAX_PRINCIPALSIZE + 14)

/*
 * NFS4_MAX_ACLSIZE -- the number of bytes in the string representation
 * of a whole ACL, regardless of the number of ACEs; used to set buffer
 * sizes.  since linux limits xattrs to 64KB anyway, we don't have to
 * worry about/can't really handle huge ACLs.  while the string
 * representation doesn't directly compare to the xattr size, this
 * is probably a reasonable guess.
 */
/* Fixme: This value is used for buffer allocation when reading from spec file */
#define NFS4_MAX_ACLSIZE	(65536)

#define NFS41ACLMAXACES		(128)
#define	ACES_2_XDRSIZE(naces) 	((sizeof(u_int) * 2) + (naces * sizeof(nfsace4i)))
#define XDRSIZE_2_ACES(sz)	((sz - (sizeof(u_int) * 2)) / sizeof(nfsace4i))
#define XDRSIZE_IS_VALID(sz)	((sz >= ((sizeof(u_int) * 2) + sizeof(nfsace4i))) && \
				(((sz - (sizeof(u_int) * 2)) % sizeof(nfsace4i)) == 0))

#define ACES_2_ACLSIZE(naces)	(sizeof(nfsacl41i) + (naces * sizeof(nfsace4i)))
#define ACLSIZE_2_ACES(sz)	((sz - (sizeof(nfsacl41i))) / sizeof(nfsace4i))
#define ACLSIZE_IS_VALID(sz)	((sz >= (sizeof(nfsacl41i) + sizeof(nfsace4i))) && \
				(((sz - sizeof(nfsacl41i)) % sizeof(nfsace4i) == 0)))

/*
 * There is an option to compile with a different xattr name.
 * This is useful for testing on server without ZFS / native NFSv4 ACLs
 *
 */
/* NFS4 acl xattr name */
#define SYSTEM_XATTR "system.nfs4_acl_xdr"
#define SECURITY_XATTR "security.nfs4acl_xdr"

#ifdef USE_SECURITY_NAMESPACE
#define ACL_NFS4_XATTR SECURITY_XATTR
#else
#define ACL_NFS4_XATTR SYSTEM_XATTR
#endif

/* Macro for finding empty tailqs */
#define TAILQ_IS_EMPTY(head) (head.tqh_first == NULL)

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)		(sizeof (x) / sizeof (x[0]))
#endif

typedef u_int32_t u32;

struct ace_container {
	struct nfs4_ace *ace;
	TAILQ_ENTRY(ace_container) l_ace;
};

TAILQ_HEAD(ace_container_list_head, ace_container);

/**** Public functions ****/

/** Manipulation functions **/
extern int			acl_nfs4_set_who(struct nfs4_ace*, int, const char*, nfs4_acl_id_t *idp);
extern struct nfs4_acl *	acl_nfs4_copy_acl(struct nfs4_acl *);
extern struct nfs4_acl *	acl_nfs4_xattr_load(char *, int, u32);
extern struct nfs4_acl *	acl_nfs4_strip(struct nfs4_acl *);
extern size_t			acl_nfs4_xattr_pack(struct nfs4_acl *, char**);

extern void			nfs4_free_acl(struct nfs4_acl *);
extern int			nfs4_acl_is_trivial_np(struct nfs4_acl *acl, int *trivialp);
extern int			nfs4_remove_ace(struct nfs4_acl *acl, struct nfs4_ace *ace);
extern int			nfs4_remove_ace_at(struct nfs4_acl *acl, unsigned int index);
extern int			nfs4_insert_ace_at(struct nfs4_acl *acl, struct nfs4_ace *ace, unsigned int index);
#define nfs4_prepend_ace(acl, ace)  nfs4_insert_ace_at(acl, ace, 0)
#define nfs4_append_ace(acl, ace)   nfs4_insert_ace_at(acl, ace, acl->naces)
extern struct nfs4_ace *	nfs4_new_ace(int is_directory, nfs4_acl_type_t type, nfs4_acl_flag_t flag,
					     nfs4_acl_perm_t access_mask, nfs4_acl_who_t whotype, nfs4_acl_id_t id);
extern struct nfs4_acl *	nfs4_new_acl(u32);

extern int			nfs4_insert_file_aces(struct nfs4_acl *acl, FILE* fd, unsigned int index);
extern int			nfs4_insert_string_aces(struct nfs4_acl *acl, const char *acl_spec, unsigned int index);
extern int			nfs4_replace_ace(struct nfs4_acl *acl, struct nfs4_ace *old_ace, struct nfs4_ace *new_ace);
extern int			nfs4_replace_ace_spec(struct nfs4_acl *acl, char *from_ace_spec, char *to_ace_spec);
extern int			nfs4_remove_file_aces(struct nfs4_acl *acl, FILE *fd);
extern int			nfs4_remove_string_aces(struct nfs4_acl *acl, char *string);
bool				acl_nfs4_inherit_entries(struct nfs4_acl *parent_aclp, struct nfs4_acl *child_aclp, bool is_dir);
bool 				acl_nfs4_calculate_inherited_acl(struct nfs4_acl *parent_aclp,
								 struct nfs4_acl *aclp,
								 mode_t mode, bool skip_mode,
								 int is_dir);

/** Get and Set ACL functions **/
extern struct nfs4_acl * 	nfs4_acl_get_file(const char *path);
extern struct nfs4_acl * 	nfs4_acl_get_fd(int fd);
extern int			nfs4_acl_set_file(struct nfs4_acl *acl, const char *path);
extern int			nfs4_acl_set_fd(struct nfs4_acl *acl, int fd);

/** Conversion functions **/
extern struct nfs4_ace *	nfs4_ace_from_text(u_int32_t is_dir, char *str);
extern char *			nfs4_acl_spec_from_file(FILE *f);


/** Access Functions **/
extern int			acl_nfs4_get_who(struct nfs4_ace*, nfs4_acl_id_t *who_id, char *who_str, size_t str_size);

extern struct nfs4_ace *	nfs4_get_first_ace(struct nfs4_acl *);
extern struct nfs4_ace *	nfs4_get_next_ace(struct nfs4_ace **);
extern struct nfs4_ace *	nfs4_get_ace_at(struct nfs4_acl *, unsigned int index);


/** Display Functions **/
extern int			nfs4_print_acl_json(char *path, int flags);
extern void			nfs4_print_acl(FILE *fp, struct nfs4_acl *acl);
extern int			nfs4_print_ace(FILE *fp, struct nfs4_ace *ace, u32 isdir);
extern int			nfs4_print_ace_verbose(struct nfs4_ace * ace, u32 isdir);

/* Flag manipulation functions */
extern bool			nfs4_aclflag_to_text(nfs4_acl_aclflags_t flags4, char **out);
extern bool			nfs4_aclflag_from_text(char *flags, nfs4_acl_aclflags_t *flags4p);


/** misc **/
extern bool			ace_is_equal(struct nfs4_ace *a, struct nfs4_ace *b);
extern bool			aces_are_equal(struct nfs4_acl *a, struct nfs4_acl *b);
extern unsigned long		strtoul_reals(char *s, int base);

/** BSD NFSv4 Display Functions **/
int	_nfs4_acl_entry_from_text(struct nfs4_acl *acl, char *, uint *index);
char	*_nfs4_acl_to_text_np(struct nfs4_acl *acl, ssize_t *, int);
int	_nfs4_format_flags(char *str, size_t size, uint var, int verbose);
int	_nfs4_format_access_mask(char *str, size_t size, uint var, int verbose);
int	_nfs4_parse_flags(const char *str, uint *var);
int	_nfs4_parse_access_mask(const char *str, uint *var);

/** JSON **/
json_t*				_nfs4_ace_to_json(struct nfs4_ace *entry, int flags);
json_t*				_nfs4_acl_to_json(struct nfs4_acl *aclp, int flags);
int				set_acl_path_json(const char *path, const char *json_text);
struct nfs4_acl*		get_acl_json(const char *json_text, bool is_dir);

#endif
