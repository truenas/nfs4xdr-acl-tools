/*  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
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
#include <string.h>
#include "libacl_nfs4.h"


char * nfs4_acl_spec_from_file(FILE *f)
{
	char ace_buf[NFS4_MAX_ACESIZE];
	char *acl_spec, *c;
	int consumed = 0;

	if (!f)
		return NULL;

	acl_spec = calloc(1, NFS4_MAX_ACLSIZE);
	if (!acl_spec)
		return NULL;

	while (fgets(ace_buf, NFS4_MAX_ACESIZE, f) != NULL) {
		if ((c = strchr(ace_buf, '#')) != NULL)
			*c = '\0';
		consumed += strlen(ace_buf);
		if (consumed > NFS4_MAX_ACLSIZE) {
			fprintf(stderr, "ERROR: maximum ACL buffer size exceeded (%d > %d).\n",
					NFS4_MAX_ACLSIZE, consumed);
			free(acl_spec);
			return NULL;
		}
		strncat(acl_spec, ace_buf, NFS4_MAX_ACESIZE);

	}

	return acl_spec;
}
