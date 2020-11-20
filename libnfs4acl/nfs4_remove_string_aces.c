/*  Copyright (c) 2006, 2007 The Regents of the University of Michigan.
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

int nfs4_remove_string_aces(struct nfs4_acl *acl, char *acl_spec)
{
	struct nfs4_ace *ace, *anti_ace;
	struct nfs4_acl *anti_acl = NULL;
	int err = -1;
	
	if (acl == NULL || acl->naces == 0) 
		goto out;

	if ((anti_acl = nfs4_new_acl(acl->is_directory)) == NULL)
		goto out;
	
	if (nfs4_insert_string_aces(anti_acl, acl_spec, 0))
		goto out;

	for (anti_ace = nfs4_get_first_ace(anti_acl); anti_ace != NULL; anti_ace = nfs4_get_next_ace(&anti_ace))
		for (ace = nfs4_get_first_ace(acl); ace != NULL; ace = nfs4_get_next_ace(&ace))
			if (!nfs4_ace_cmp(anti_ace, ace))
				nfs4_remove_ace(acl, ace);
	err = 0;
out:
	if (anti_acl)
		nfs4_free_acl(anti_acl);

	return  err;
}
