

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

const struct nfs4_ace owner_basic_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE | NFS4_ACE_OWNER),
        .whotype = NFS4_ACL_WHO_OWNER,
	.who = NFS4_ACL_WHO_OWNER_STRING,
};

const struct nfs4_ace named_basic_full_control = (struct nfs4_ace) {
	.type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	.access_mask = NFS4_ACE_FULL_SET,
	.flag = (NFS4_ACE_FILE_INHERIT_ACE | NFS4_ACE_DIRECTORY_INHERIT_ACE),
        .whotype = NFS4_ACL_WHO_NAMED,
	.who = "0",
};

const struct {
	const char *name;
	const struct nfs4_ace ace;
	bool verbose;
} json2ace[] = {
	{ "owner-full_control-basic", owner_basic_full_control, false },
	{ "owner-full_control-advanced", owner_basic_full_control, true },
	{ "named-full_control-basic", named_basic_full_control, false },
};
#endif
