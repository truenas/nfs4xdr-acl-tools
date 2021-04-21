/*-
 * Copyright 2021 iXsystems, Inc.
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


#ifndef TORTURE_H
#define TORTURE_H 1
#include "libacl_nfs4.h"

const struct {
	size_t size;
	const char *name;
	int err;
} attrs[] = {
	{ 4, "extra-small", EINVAL },
	{ ACES_2_XDRSIZE(1), "small", 0 },
	{ ACES_2_XDRSIZE(8), "medium", 0 },
	{ (ACES_2_XDRSIZE(64) - 1), "medium-invalid", EINVAL },
	{ ACES_2_XDRSIZE(120), "large", 0 },
	{ ACES_2_XDRSIZE(1024), "extra-large", E2BIG },
	{ (ACES_2_XDRSIZE(14535) -1), "extra-large-invald", E2BIG },
	{ (ACES_2_XDRSIZE(1000000) -1), "ludicrously-invald", E2BIG },
};

const struct nfs4_ace owner_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE),
        .whotype = NFS4_ACL_WHO_OWNER,
	.who_id = -1,
};

const struct nfs4_ace group_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE | NFS4_ACE_IDENTIFIER_GROUP),
        .whotype = NFS4_ACL_WHO_GROUP,
	.who_id = -1,
};

const struct nfs4_ace everyone_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE),
        .whotype = NFS4_ACL_WHO_EVERYONE,
	.who_id = -1,
};

const struct nfs4_ace named_user_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE),
        .whotype = NFS4_ACL_WHO_NAMED,
	.who_id = 8675309,
};

const struct nfs4_ace named_group_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE | NFS4_ACE_IDENTIFIER_GROUP),
        .whotype = NFS4_ACL_WHO_NAMED,
	.who_id = 8675309,
};

const struct {
	const char *name;
	const struct nfs4_ace ace;
} acetemplates[] = {
	{ "owner-full_control", owner_full_control },
	{ "group-full_control", group_full_control },
	{ "everyone-full_control", everyone_full_control },
	{ "named-user-full_control-basic", named_user_full_control },
	{ "named-group-full_control-basic", named_user_full_control },
};
#endif
