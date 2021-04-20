/*
 *  NFSv4 protocol definitions.
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
 *  Andy Adamson   <andros@umich.edu>
 */

#include<sys/types.h>
#include<sys/queue.h>
#define NFS4_DEBUG 1

#define NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE 0
#define NFS4_ACE_ACCESS_DENIED_ACE_TYPE  1
#define NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE   2
#define NFS4_ACE_SYSTEM_ALARM_ACE_TYPE   3

#define ACL4_SUPPORT_ALLOW_ACL 0x01
#define ACL4_SUPPORT_DENY_ACL  0x02
#define ACL4_SUPPORT_AUDIT_ACL 0x04
#define ACL4_SUPPORT_ALARM_ACL 0x08

#define NFS4_ACE_FILE_INHERIT_ACE             0x00000001
#define NFS4_ACE_DIRECTORY_INHERIT_ACE        0x00000002
#define NFS4_ACE_NO_PROPAGATE_INHERIT_ACE     0x00000004
#define NFS4_ACE_INHERIT_ONLY_ACE             0x00000008
#define NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG   0x00000010
#define NFS4_ACE_FAILED_ACCESS_ACE_FLAG       0x00000020
#define NFS4_ACE_IDENTIFIER_GROUP             0x00000040
#define NFS4_ACE_INHERITED_ACE                0x00000080
#define NFS4_ACE_OWNER                        0x00001000
#define NFS4_ACE_GROUP                        0x00002000
#define NFS4_ACE_EVERYONE                     0x00004000

#define NFS4_IS_GROUP(flag) (flag & NFS4_ACE_IDENTIFIER_GROUP)
#define NFS4_ACE_FLAGS_DIRECTORY             (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE | NFS4_ACE_INHERIT_ONLY_ACE | \
	                                      NFS4_ACE_NO_PROPAGATE_INHERIT_ACE)

#define NFS4_ACE_READ_DATA                    0x00000001
#define NFS4_ACE_LIST_DIRECTORY               0x00000001
#define NFS4_ACE_WRITE_DATA                   0x00000002
#define NFS4_ACE_ADD_FILE                     0x00000002
#define NFS4_ACE_APPEND_DATA                  0x00000004
#define NFS4_ACE_ADD_SUBDIRECTORY             0x00000004
#define NFS4_ACE_READ_NAMED_ATTRS             0x00000008
#define NFS4_ACE_WRITE_NAMED_ATTRS            0x00000010
#define NFS4_ACE_EXECUTE                      0x00000020
#define NFS4_ACE_DELETE_CHILD                 0x00000040
#define NFS4_ACE_READ_ATTRIBUTES              0x00000080
#define NFS4_ACE_WRITE_ATTRIBUTES             0x00000100
#define NFS4_ACE_DELETE                       0x00010000
#define NFS4_ACE_READ_ACL                     0x00020000
#define NFS4_ACE_WRITE_ACL                    0x00040000
#define NFS4_ACE_WRITE_OWNER                  0x00080000
#define NFS4_ACE_SYNCHRONIZE                  0x00100000

#define NFS4_ACE_GENERIC_READ                (NFS4_ACE_READ_DATA | NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_READ_ACL | NFS4_ACE_SYNCHRONIZE)
#define NFS4_ACE_GENERIC_WRITE               (NFS4_ACE_WRITE_DATA | NFS4_ACE_APPEND_DATA | NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_WRITE_ATTRIBUTES | \
                                              NFS4_ACE_WRITE_NAMED_ATTRS | NFS4_ACE_READ_ACL | NFS4_ACE_WRITE_ACL | NFS4_ACE_DELETE_CHILD | NFS4_ACE_SYNCHRONIZE)
#define NFS4_ACE_GENERIC_EXECUTE             (NFS4_ACE_EXECUTE | NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_ACL | NFS4_ACE_SYNCHRONIZE)
#define NFS4_ACE_MASK_ALL                    (NFS4_ACE_GENERIC_READ | NFS4_ACE_GENERIC_WRITE | NFS4_ACE_GENERIC_EXECUTE | NFS4_ACE_DELETE | NFS4_ACE_WRITE_OWNER)
#define NFS4_ACE_BASE_ALLOW_PSARC            (NFS4_ACE_READ_ACL | NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_SYNCHRONIZE | NFS4_ACE_READ_NAMED_ATTRS)
#define NFS4_ACE_USER_ALLOW_PSARC            (NFS4_ACE_WRITE_ACL | NFS4_ACE_APPEND_DATA | NFS4_ACE_WRITE_OWNER | NFS4_ACE_WRITE_ATTRIBUTES | NFS4_ACE_WRITE_NAMED_ATTRS)

#define NFS4_ACE_FULL_SET                    NFS4_ACE_MASK_ALL
#define NFS4_ACE_READ_SET                    (NFS4_ACE_READ_DATA | NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_READ_ACL)
#define NFS4_ACE_WRITE_SET                   (NFS4_ACE_WRITE_DATA | NFS4_ACE_APPEND_DATA | NFS4_ACE_WRITE_ATTRIBUTES | NFS4_ACE_WRITE_NAMED_ATTRS)
#define NFS4_ACE_MODIFY_SET                  NFS4_ACE_FULL_SET & ~(NFS4_ACE_WRITE_ACL | NFS4_ACE_WRITE_OWNER)

enum nfs4_acl_whotype {
	NFS4_ACL_WHO_NAMED = 0,
	NFS4_ACL_WHO_OWNER,
	NFS4_ACL_WHO_GROUP,
	NFS4_ACL_WHO_EVERYONE,
};

#define NFS4_ACL_WHO_OWNER_STRING	"OWNER@"
#define NFS4_ACL_WHO_GROUP_STRING	"GROUP@"
#define NFS4_ACL_WHO_EVERYONE_STRING	"EVERYONE@"

#define ACL_AUTO_INHERIT                                0x0001
#define ACL_PROTECTED                                   0x0002
#define ACL_DEFAULTED                                   0x0004
#define ACL_FLAGS_ALL   (ACL_AUTO_INHERIT|ACL_PROTECTED|ACL_DEFAULTED)

/*
 * this is my best guess about the principal name -- there are a lot of different
 * ideas.  utmp.h limits usernames to 32 characters, but v4 names (excluding the
 * domain component) up to 128 characters are tolerated in idmapd.c.  so, 128.
 *
 * DNS limits domain names to roughly 256 characters (more like 253 in practice,
 * but call it 256), but nfsidmap.h seems to indicate v4 domains could have up to
 * 512 characters.  i can't see a reason not to trust the DNS limit.  so, 256.
 *
 * add 1 for '@', 1 for NULL.
 */
#define NFS4_MAX_PRINCIPALSIZE  (128 + 256 + 1 + 1)

typedef u_int32_t nfs4_acl_type_t;
typedef u_int32_t nfs4_acl_flag_t;
typedef u_int32_t nfs4_acl_perm_t;
typedef u_int32_t nfs4_acl_aclflags_t;
typedef u_int32_t nfs4_acl_who_t;
typedef uid_t     nfs4_acl_id_t;

struct nfs4_ace {
	nfs4_acl_type_t		type;
	nfs4_acl_who_t		whotype;
	nfs4_acl_id_t		who_id;	
	nfs4_acl_flag_t		flag;
	nfs4_acl_perm_t		access_mask;
	TAILQ_ENTRY(nfs4_ace)	l_ace;
};

TAILQ_HEAD(ace_list_head, nfs4_ace);

struct nfs4_acl {
	u_int32_t		naces;
	nfs4_acl_aclflags_t	aclflags4;
	u_int32_t		is_directory;
	struct ace_list_head	ace_head;
};
