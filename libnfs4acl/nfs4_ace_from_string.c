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
 *  Copyright (c) 2005, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
 *  David M. Richter <richterd@citi.umich.edu>
 *  Alexis Mackenzie <allamack@umich.edu>
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
#include <ctype.h>
#include "libacl_nfs4.h"

/*
 * An array of pointers to hold the parsed acetype, aceflag, acewho and
 * acemask.
 */
#define NUMFIELDS 	4
#define TYPE_INDEX	0
#define FLAG_INDEX	1
#define WHO_INDEX	2
#define MASK_INDEX	3


/*
 * strrep - replace all occurrences of 'from' with 'to' in the null-
 *  terminated string 's'.  why isn't there one of these already?
 */
void
strrep(char *s, char from, char to)
{
	while ((s = strchr(s, from)) != NULL)
		*s = to;
}

void
free_fields(char *fields[NUMFIELDS])
{
	int i;

	for (i = 0; i < NUMFIELDS; i++)
		if (fields[i] != NULL)
			free(fields[i]);
}

int
parse_alloc_fields(char *buf, char *fields[NUMFIELDS])
{
	char *field;
	int i, len, count = 0;

	if (!buf)
		return -EINVAL;

	memset(fields, 0, sizeof(fields));

	for (i = 0; buf[i] != '\0'; i++) {
		if (buf[i] == ':')
			count++;
	}
	if (count != 3)
		goto out_free;

	for (i = 0; i < NUMFIELDS; i++) {
		field = strsep(&buf, ":");
		len = strlen(field);
		fields[i] = malloc(len + 1);
		if (!fields[i])
			goto out_free;
		if (len > 0)
			memcpy(fields[i], field, len);
		fields[i][len] = 0;
	}

	if (!fields[TYPE_INDEX][0] || !fields[WHO_INDEX][0] || !fields[MASK_INDEX][0])
		goto out_free;

	return 0;
out_free:
	free_fields(fields);
	return -ENOMEM;
}

/*
 * returns pointer to nfs4_ace on success, NULL on failure
 */

struct nfs4_ace * nfs4_ace_from_string(char *ace_buf, int is_dir)
{
	int ret;
	char *fields[NUMFIELDS], *bufp, *field;
	u32 type, flags = 0, mask = 0;
	int buflen;
	struct nfs4_ace *ace = NULL;

	strrep(ace_buf, '\n', '\0');

	/* e.g., we got a blank line or a comment */
	if (*ace_buf == '\0' || *ace_buf == '#')
		return NULL;

	/* parse_alloc_fields had split up ace_buf so now we copy it to bufp */
	bufp = malloc(strlen(ace_buf) + 1);
	if (!bufp)
		goto out_free;
	strcpy(bufp,ace_buf);

	ret = parse_alloc_fields(bufp, fields);
	free(bufp);
	if (ret < 0) {
		fprintf(stderr,"Scanning ACE string '%s' failed.\n", ace_buf);
		goto out;
	} else if (strlen(fields[WHO_INDEX]) > NFS4_MAX_PRINCIPALSIZE) {
		fprintf(stderr,"Principal \'%s\' is too large.\n",fields[WHO_INDEX]);
		goto out_free;
	}

	switch (*fields[TYPE_INDEX]) {
		case TYPE_ALLOW:
			type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
			break;
		case TYPE_DENY:
			type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
			break;
		case TYPE_AUDIT:
			type = NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE;
			break;
		case TYPE_ALARM:
			type = NFS4_ACE_SYSTEM_ALARM_ACE_TYPE;
			break;
		default:
			fprintf(stderr,"Bad Ace Type:%c\n", *fields[TYPE_INDEX]);
			goto out_free;
	}

	field = fields[FLAG_INDEX];
	for (buflen = strlen(field); buflen > 0; buflen--) {
		switch (*field) {
			case FLAG_FILE_INHERIT:
				flags |= NFS4_ACE_FILE_INHERIT_ACE;
				break;
			case FLAG_DIR_INHERIT:
				flags |= NFS4_ACE_DIRECTORY_INHERIT_ACE;
				break;
			case FLAG_NO_PROPAGATE_INHERIT:
				flags |= NFS4_ACE_NO_PROPAGATE_INHERIT_ACE;
				break;
			case FLAG_INHERIT_ONLY:
				flags |= NFS4_ACE_INHERIT_ONLY_ACE;
				break;
			case FLAG_SUCCESSFUL_ACCESS:
				flags |= NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG;
				break;
			case FLAG_FAILED_ACCESS:
				flags |= NFS4_ACE_FAILED_ACCESS_ACE_FLAG;
				break;
			case FLAG_GROUP:
				flags |= NFS4_ACE_IDENTIFIER_GROUP;
				break;
			case FLAG_OWNER_AT:
				flags |= NFS4_ACE_OWNER;
				break;
			case FLAG_GROUP_AT:
				flags |= NFS4_ACE_GROUP;
				break;
			case FLAG_EVERYONE_AT:
				flags |= NFS4_ACE_EVERYONE;
				break;
			default:
				fprintf(stderr,"Bad Ace Flag:%c\n", *field);
				goto out_free;
		}
		field++;
	}

	if (!strcmp(fields[WHO_INDEX], NFS4_ACL_WHO_GROUP_STRING))
			flags |= NFS4_ACE_IDENTIFIER_GROUP;

	field = fields[MASK_INDEX];
	for (buflen = strlen(field); buflen > 0; buflen--) {
		ret = -EINVAL;
		switch (*field) {
//			case PERM_LIST_DIR:
//				if (!(is_dir & NFS4_ACL_ISDIR))
//					goto out_not_dir;
//				mask |= NFS4_ACE_LIST_DIRECTORY;
//				break;
//			case PERM_CREATE_FILE:
//				if (!(is_dir & NFS4_ACL_ISDIR))
//					goto out_not_dir;
//				mask |= NFS4_ACE_ADD_FILE;
//				break;
//			case PERM_CREATE_SUBDIR:
//				if (!(is_dir & NFS4_ACL_ISDIR))
//					goto out_not_dir;
//				mask |= NFS4_ACE_ADD_SUBDIRECTORY;
//				break;
			case PERM_DELETE_CHILD:
				if (is_dir)
					mask |= NFS4_ACE_DELETE_CHILD;
				break;
			case PERM_READ_DATA:   /* aka PERM_LIST_DIR */
				mask |= NFS4_ACE_READ_DATA;
				break;
			case PERM_WRITE_DATA:  /* aka PERM_CREATE_FILE */
				mask |= NFS4_ACE_WRITE_DATA;
				break;
			case PERM_APPEND_DATA: /* aka PERM_CREATE_SUBDIR */
				mask |= NFS4_ACE_APPEND_DATA;
				break;
			case PERM_DELETE:
				mask |= NFS4_ACE_DELETE;
				break;
			case PERM_EXECUTE:
				mask |= NFS4_ACE_EXECUTE;
				break;
			case PERM_READ_ATTR:
				mask |= NFS4_ACE_READ_ATTRIBUTES;
				break;
			case PERM_WRITE_ATTR:
				mask |= NFS4_ACE_WRITE_ATTRIBUTES;
				break;
			case PERM_READ_NAMED_ATTR:
				mask |= NFS4_ACE_READ_NAMED_ATTRS;
				break;
			case PERM_WRITE_NAMED_ATTR:
				mask |= NFS4_ACE_WRITE_NAMED_ATTRS;
				break;
			case PERM_READ_ACL:
				mask |= NFS4_ACE_READ_ACL;
				break;
			case PERM_WRITE_ACL:
				mask |= NFS4_ACE_WRITE_ACL;
				break;
			case PERM_WRITE_OWNER:
				mask |= NFS4_ACE_WRITE_OWNER;
				break;
			case PERM_SYNCHRONIZE:
				mask |= NFS4_ACE_SYNCHRONIZE;
				break;

			/* expand the perms that aim to simulate POSIX mode bits */
			case PERM_GENERIC_READ:
				mask |= NFS4_ACE_GENERIC_READ;
				break;
			case PERM_GENERIC_WRITE:
				mask |= NFS4_ACE_GENERIC_WRITE;
				break;
			case PERM_GENERIC_EXECUTE:
				mask |= NFS4_ACE_GENERIC_EXECUTE;
				break;
			default:
				fprintf(stderr,"Bad Ace Mask:%c\n", *field);
				goto out_free;
		}
		field++;
	}

	ace = nfs4_new_ace(is_dir, type, flags, mask, 
			acl_nfs4_get_whotype(fields[WHO_INDEX]), fields[WHO_INDEX]);

	if (ace == NULL) {
		fprintf(stderr,"ACE is NULL.\n");
		goto out_free;
	} else if (12 + strlen(ace->who) > NFS4_MAX_ACESIZE) {
		/* ace type,flag,access_mask are each u32 (3 * 4 bytes) */
		fprintf(stderr,"ACE is too large.\n");
		goto out_free;
	}

out_free:
	free_fields(fields);
out:
	return ace;
}
