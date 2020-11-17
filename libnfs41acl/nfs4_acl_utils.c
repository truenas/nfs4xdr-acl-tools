/*
 *  NFSv4 ACL manipulation / accessor stuff
 *
 *  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  David M. Richter <richterd@umich.edu>
 *  Marius Eriksen <marius@monkey.org>
 *  Alexis Mackenzie <allamack@umich.edu>
 *  Nathan Gallaher <ngallahe@umich.edu>
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


inline struct nfs4_ace* nfs4_get_first_ace(struct nfs4_acl *acl)
{
        if (acl == NULL)
                return NULL;

        return acl->ace_head.tqh_first;
}

inline struct nfs4_ace* nfs4_get_next_ace(struct nfs4_ace **ace)
{
        if (ace == NULL || (*ace) == NULL)
                return NULL;

        (*ace) = (*ace)->l_ace.tqe_next;
        return *ace;
}

struct nfs4_ace* nfs4_get_ace_at(struct nfs4_acl *acl, unsigned int index)
{
	struct nfs4_ace *ace;
	int i;

	if (index >= acl->naces)
		return NULL;

	ace = nfs4_get_first_ace(acl);
	for (i = 0; i < index; i++)
		ace = nfs4_get_next_ace(&ace);

	return ace;
}

int nfs4_insert_ace_at(struct nfs4_acl *acl, struct nfs4_ace *ace, unsigned int index)
{
	struct nfs4_ace *ap;

	if (acl == NULL || ace == NULL || index > acl->naces)
		return -1;

	if (index == 0) {
		TAILQ_INSERT_HEAD(&acl->ace_head, ace, l_ace);
	} else if (index == acl->naces) {
		TAILQ_INSERT_TAIL(&acl->ace_head, ace, l_ace);
	} else {
		if ((ap = nfs4_get_ace_at(acl, index - 1)) == NULL)
			return -1;

		TAILQ_INSERT_AFTER(&acl->ace_head, ap, ace, l_ace);
	}
	acl->naces++;

	return 0;
}

int nfs4_remove_ace(struct nfs4_acl *acl, struct nfs4_ace *ace)
{
	if (acl == NULL || ace == NULL)
		return -1;

	TAILQ_REMOVE(&acl->ace_head, ace, l_ace);
	free(ace);
	acl->naces--;

	return 0;
}

int nfs4_remove_ace_at(struct nfs4_acl *acl, unsigned int index)
{
	return nfs4_remove_ace(acl, nfs4_get_ace_at(acl, index));
}

int nfs4_replace_ace(struct nfs4_acl *acl, struct nfs4_ace *old_ace, struct nfs4_ace *new_ace)
{
	if (acl == NULL || old_ace == NULL || new_ace == NULL)
		return -1;

	TAILQ_INSERT_AFTER(&acl->ace_head, old_ace, new_ace, l_ace);
	TAILQ_REMOVE(&acl->ace_head, old_ace, l_ace);

	return 0;
}

/* NOTE: unlike other functions, this doesn't take 'acl_specs'; rather, two
 *       individual 'ace_specs'
 */
int nfs4_replace_ace_spec(struct nfs4_acl *acl, char *from_ace_spec, char *to_ace_spec)
{
	struct nfs4_ace *from_ace, *to_ace, *orig_ace, *new_ace;
	int err = -1;

	if (acl == NULL)
		goto out;

	if ((from_ace = nfs4_ace_from_string(from_ace_spec, acl->is_directory)) == NULL)
		goto out;

	if ((to_ace = nfs4_ace_from_string(to_ace_spec, acl->is_directory)) == NULL)
		goto free_from;

	for (orig_ace = nfs4_get_first_ace(acl); orig_ace != NULL; nfs4_get_next_ace(&orig_ace)) {
		if (!nfs4_ace_cmp(from_ace, orig_ace)) {
			new_ace = nfs4_new_ace(acl->is_directory, to_ace->type, to_ace->flag,
					to_ace->access_mask, to_ace->whotype, to_ace->who);
			if (new_ace == NULL)
				goto frito;
			nfs4_replace_ace(acl, orig_ace, new_ace);
			free(orig_ace);
			orig_ace = new_ace; /* so the for-loop turns over right */
		}
	}
	err = 0;
frito:
	free(to_ace);
free_from:
	free(from_ace);
out:
	return err;
}

/* XXX: for now, just doing equality testing.
 *      if we end up going for a canonical ordering, this'll expand.
 *      assumes no NULLs.
 *      behavior `a la strcmp().
 */
int nfs4_ace_cmp(struct nfs4_ace *lhs, struct nfs4_ace *rhs)
{
	if ((lhs->type == rhs->type)
			&& (lhs->flag == rhs->flag)
			&& (lhs->access_mask == rhs->access_mask)
			&& (!strncmp(lhs->who, rhs->who, NFS4_MAX_PRINCIPALSIZE)))
		return 0;
	return 1;
}
