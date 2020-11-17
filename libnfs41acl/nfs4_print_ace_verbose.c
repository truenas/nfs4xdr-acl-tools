/*
 *  NFSv4 ACL Code
 *  Print the contents of an nfs4 ACE
 *
 *  Permission mapping:
 *  r - NFS4_ACE_READ_DATA
 *  l - NFS4_ACE_LIST_DIRECTORY
 *  w - NFS4_ACE_WRITE_DATA
 *  f - NFS4_ACE_ADD_FILE
 *  a - NFS4_ACE_APPEND_DATA
 *  s - NFS4_ACE_ADD_SUBDIRECTORY
 *  n - NFS4_ACE_READ_NAMED_ATTRS
 *  N - NFS4_ACE_WRITE_NAMED_ATTRS
 *  x - NFS4_ACE_EXECUTE
 *  D - NFS4_ACE_DELETE_CHILD
 *  t - NFS4_ACE_READ_ATTRIBUTES
 *  T - NFS4_ACE_WRITE_ATTRIBUTES
 *  d - NFS4_ACE_DELETE
 *  c - NFS4_ACE_READ_ACL
 *  C - NFS4_ACE_WRITE_ACL
 *  o - NFS4_ACE_WRITE_OWNER
 *  y - NFS4_ACE_SYNCHRONIZE
 *
 *
 *  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Nathaniel Gallaher <ngallahe@umich.edu>
 *  David M. Richter <richterd@citi.umich.edu>
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

#include <stdio.h>
#include "libacl_nfs4.h"

int nfs4_print_ace_verbose(struct nfs4_ace * ace, u32 is_dir)
{
	int result;
	char * who;
	char * whotype_s;
	char * type_s;
	u32 type;
	u32 flag;
	u32 whotype;
	u32 mask;


	result = acl_nfs4_get_who(ace, &whotype, &who);
	if (result != 0)
		goto unexp_failed;

	switch(whotype) {
		case NFS4_ACL_WHO_NAMED:
			whotype_s = "NFS4_ACL_WHO_NAMED";
			break;
		case NFS4_ACL_WHO_OWNER:
			whotype_s = "NFS4_ACL_WHO_OWNER";
			break;
		case NFS4_ACL_WHO_GROUP:
			whotype_s = "NFS4_ACL_WHO_GROUP";
			break;
		case NFS4_ACL_WHO_EVERYONE:
			whotype_s = "NFS4_ACL_WHO_EVERYONE";
			break;
		default:
			free(who);
			printf("Bad whotype: %d", whotype);
			goto unexp_failed;
	}
	printf("  Whotype:\t%s\n", whotype_s);
	printf("  Who:\t\t%s\n", who);
	free(who);

	switch(ace->type) {
		case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
			type_s = "ACCESS_ALLOWED";
			break;
		case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
			type_s = "ACCESS_DENIED";
			break;
		case NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE:
			type_s = "SYSTEM_AUDIT";
			break;
		case NFS4_ACE_SYSTEM_ALARM_ACE_TYPE:
			type_s = "SYSTEM_ALARM";
			break;
		default:
			printf("Bad Ace Type:%d\n", type);
			goto unexp_failed;
	}
	printf("  Type:\t\t%s\n", type_s);


	flag = ace->flag;
	printf("  Flags:\n");

	if (flag & NFS4_ACE_FILE_INHERIT_ACE)
		printf("\t\tNFS4_ACE_FILE_INHERIT_ACE\n");
	if (flag & NFS4_ACE_DIRECTORY_INHERIT_ACE)
		printf("\t\tNFS4_ACE_DIRECTORY_INHERIT_ACE\n");
	if (flag & NFS4_ACE_NO_PROPAGATE_INHERIT_ACE)
		printf("\t\tNFS4_ACE_NO_PROPAGATE_INHERIT_ACE\n");
	if (flag & NFS4_ACE_INHERIT_ONLY_ACE)
		printf("\t\tNFS4_ACE_INHERIT_ONLY_ACE\n");
	if (flag & NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG)
		printf("\t\tNFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG\n");
	if (flag & NFS4_ACE_FAILED_ACCESS_ACE_FLAG)
		printf("\t\tNFS4_ACE_FAILED_ACCESS_ACE_FLAG\n");
	if (flag & NFS4_ACE_IDENTIFIER_GROUP)
		printf("\t\tNFS4_ACE_IDENTIFIER_GROUP\n");
	if (flag & NFS4_ACE_OWNER)
		printf("\t\tNFS4_ACE_OWNER\n");
	if (flag & NFS4_ACE_GROUP)
		printf("\t\tNFS4_ACE_GROUP\n");
	if (flag & NFS4_ACE_EVERYONE)
		printf("\t\tNFS4_ACE_EVERYONE\n");


	mask = ace->access_mask;
	printf("  Perms:\t");

	if (is_dir & NFS4_ACL_ISDIR) {
		if (mask & NFS4_ACE_LIST_DIRECTORY)
			printf("l");
		if (mask & NFS4_ACE_ADD_FILE)
			printf("f");
		if (mask & NFS4_ACE_ADD_SUBDIRECTORY)
			printf("s");
		if (mask & NFS4_ACE_DELETE_CHILD)
			printf("D");
	} else {
		if (mask & NFS4_ACE_READ_DATA)
			printf("r");
		if (mask & NFS4_ACE_WRITE_DATA)
			printf("w");
		if (mask & NFS4_ACE_APPEND_DATA)
			printf("a");
	}
	if (mask & NFS4_ACE_READ_NAMED_ATTRS)
		printf("n");
	if (mask & NFS4_ACE_WRITE_NAMED_ATTRS)
		printf("N");
	if (mask & NFS4_ACE_EXECUTE)
		printf("x");
	if (mask & NFS4_ACE_READ_ATTRIBUTES)
		printf("t");
	if (mask & NFS4_ACE_WRITE_ATTRIBUTES)
		printf("T");
	if (mask & NFS4_ACE_DELETE)
		printf("d");
	if (mask & NFS4_ACE_READ_ACL)
		printf("c");
	if (mask & NFS4_ACE_WRITE_ACL)
		printf("C");
	if (mask & NFS4_ACE_WRITE_OWNER)
		printf("o");
	if (mask & NFS4_ACE_SYNCHRONIZE)
		printf("y");
	printf("\n");

	return 0;

unexp_failed:
	return -1;
}

