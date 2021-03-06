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

#include <string.h>
#include "libacl_nfs4.h"

/*
 * nfs4_insert_string_aces - read ACE entries from spec string into struct nfs4_acl
 */

int nfs4_insert_string_aces(struct nfs4_acl *acl, const char *acl_spec, unsigned int index)
{
	char *s = NULL, *sp = NULL, *ssp = NULL;
	int res = 0;
	bool is_append;

	if (acl == NULL || acl_spec == NULL) {
		errno = EINVAL;
		goto out_failed;
	}

	is_append = ((acl->naces == 0) || (index == acl->naces + 1));

	if ((s = sp = strdup(acl_spec)) == NULL)
		goto out_failed;

	while ((ssp = strsep(&sp, " ,\t\n\r")) != NULL) {
		if (!strlen(ssp))
			continue;

		/*
		 * Take more efficient path if this is an append operation.I
		 */
		if (is_append) {
			res = _nfs4_acl_entry_from_text(acl, ssp, NULL);
		}
		else {
			res = _nfs4_acl_entry_from_text(acl, ssp, &index);
			index++;
		}
		if (res != 0) {
			fprintf(stderr, "failed to get entry from text: %s\n", strerror(errno));
			goto out_failed;
		}
	}
	if (acl->naces == 0)
		goto out_failed;

out:
	if (s)
		free(s);
	return res;

out_failed:
	res = -1;
	goto out;
}
