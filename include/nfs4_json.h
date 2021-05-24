/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 iXsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	NFS4_JSON_H
#define	NFS4_JSON_H 1

#include <jansson.h>
#ifndef LIBACL_NFS4_H
#include "libacl_nfs4.h"
#endif

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)		(sizeof (x) / sizeof (x[0]))
#endif

#define	BASIC_FULL_CONTROL	(NFS4_ACE_FULL_SET)
#define	BASIC_MODIFY		(NFS4_ACE_MODIFY_SET)
#define	BASIC_READ		(NFS4_ACE_READ_SET | NFS4_ACE_EXECUTE)
#define	BASIC_TRAVERSE		(NFS4_ACE_EXECUTE | NFS4_ACE_READ_ATTRIBUTES | \
					 NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_READ_ACL)

#define	BASIC_INHERIT		(NFS4_ACE_FILE_INHERIT_ACE | \
					 NFS4_ACE_DIRECTORY_INHERIT_ACE)
#define	BASIC_NOINHERIT		(0)

const struct {
	nfs4_acl_flag_t flag;
	const char *name;
} flags2txt[] = {
	{ NFS4_ACE_FILE_INHERIT_ACE, "FILE_INHERIT"},
	{ NFS4_ACE_DIRECTORY_INHERIT_ACE, "DIRECTORY_INHERIT"},
	{ NFS4_ACE_INHERIT_ONLY_ACE, "INHERIT_ONLY"},
	{ NFS4_ACE_NO_PROPAGATE_INHERIT_ACE, "NO_PROPAGATE_INHERIT"},
	{ NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG, "SUCCESSFUL_ACCESS"},
	{ NFS4_ACE_FAILED_ACCESS_ACE_FLAG, "FAILED_ACCESS"},
	{ NFS4_ACE_INHERITED_ACE, "INHERITED"},
};

const struct {
	nfs4_acl_perm_t perm;
	const char *name;
} perms2txt[] = {
	{ NFS4_ACE_READ_DATA, "READ_DATA"},
	{ NFS4_ACE_WRITE_DATA, "WRITE_DATA"},
	{ NFS4_ACE_EXECUTE, "EXECUTE"},
	{ NFS4_ACE_APPEND_DATA, "APPEND_DATA"},
	{ NFS4_ACE_DELETE_CHILD, "DELETE_CHILD"},
	{ NFS4_ACE_DELETE, "DELETE"},
	{ NFS4_ACE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
	{ NFS4_ACE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"},
	{ NFS4_ACE_READ_NAMED_ATTRS, "READ_NAMED_ATTRS"},
	{ NFS4_ACE_WRITE_NAMED_ATTRS, "WRITE_NAMED_ATTRS"},
	{ NFS4_ACE_READ_ACL, "READ_ACL"},
	{ NFS4_ACE_WRITE_ACL, "WRITE_ACL"},
	{ NFS4_ACE_WRITE_OWNER, "WRITE_OWNER"},
	{ NFS4_ACE_SYNCHRONIZE, "SYNCHRONIZE"},
};

const struct {
	nfs4_acl_type_t type;
	const char *name;
} type2txt[] = {
	{ NFS4_ACE_READ_DATA, "READ_DATA"},
	{ NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE, "ALLOW"},
	{ NFS4_ACE_ACCESS_DENIED_ACE_TYPE, "DENY"},
	{ NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE, "AUDIT"},
	{ NFS4_ACE_SYSTEM_ALARM_ACE_TYPE, "ALARM"},
};

const struct {
	nfs4_acl_aclflags_t flag;
	const char *name;
} aclflags2txt[] = {
	{ ACL_AUTO_INHERIT, "AUTOINHERIT"},
	{ ACL_PROTECTED, "PROTECTED"},
	{ ACL_DEFAULTED, "DEFAULTED"},
};

const struct {
	nfs4_acl_perm_t perm;
	const char *name;
} basicperms2txt[] = {
	{ BASIC_FULL_CONTROL, "FULL_CONTROL"},
	{ BASIC_MODIFY, "MODIFY"},
	{ BASIC_READ, "READ"},
	{ BASIC_TRAVERSE, "TRAVERSE"},
};

const struct {
	nfs4_acl_flag_t flag;
	const char *name;
} basicflags2txt[] = {
	{ BASIC_INHERIT, "INHERIT"},
	{ BASIC_NOINHERIT, "NOINHERIT"},
};
#endif /* NFS4_JSON_H */
