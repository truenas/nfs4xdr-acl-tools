 
/*  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *  Jeff Sedlak <jsedlak@umich.edu>
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

#include "libacl_nfs4.h"


/*returns a pointer to an ace formed from the given parameters*/

struct nfs4_ace *nfs4_new_ace(int is_directory,
			      nfs4_acl_type_t type,
			      nfs4_acl_flag_t flag,
			      nfs4_acl_perm_t access_mask,
			      nfs4_acl_who_t whotype, nfs4_acl_id_t id)
{
	struct nfs4_ace *ace = NULL;

	ace = calloc(1, sizeof(struct nfs4_ace));
	if (ace == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ace->type = type;
	ace->flag = flag;
	ace->access_mask = access_mask & NFS4_ACE_MASK_ALL;
	ace->whotype = whotype;
	ace->who_id = id;
#if 0
	/*
	 * Original nfs4-acl-tools prevents setting DENY aces for
	 * various write bits. Purpose of this is unclear. Possibly
	 * related to conversion to POSIX1e ACLs. FreeBSD allows
	 * these to be set and so we have removed this restriction.
	 */
	if( type == NFS4_ACE_ACCESS_DENIED_ACE_TYPE )
		access_mask = access_mask & ~(NFS4_ACE_MASK_IGNORE);
#endif
	if (!is_directory) {
		access_mask &= ~NFS4_ACE_DELETE_CHILD;
	}
	if (!is_directory && (flag & NFS4_ACE_FLAGS_DIRECTORY)) {
#if NFS4_DEBUG
		fprintf(stderr, "Flags are invalid for a directory: 0x%08x\n",
			flag);
#endif
		free(ace);
		errno = EINVAL;
		return NULL;
	}

#if NFS4_DEBUG
	fprintf(stderr, "nfs4_new_ace(): type: %d, flag: 0x%08x, access_mask: 0x%08x, "
	    "whotype: 0x%08x, id: %d\n", ace->type, ace->flag, ace->access_mask,
	    ace->whotype, ace->who_id);
#endif

	return ace;
}
