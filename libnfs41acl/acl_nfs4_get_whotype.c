/*
 *  NFSv4 ACL Code
 *  Get the whotype of the who string passed
 *
 *  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *  Nathaniel Gallaher <ngallahe@umich.edu>
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

inline int
acl_nfs4_get_whotype(char *p)
{
	if (0 == strcmp(p, NFS4_ACL_WHO_OWNER_STRING) &&
			strlen(p) == strlen(NFS4_ACL_WHO_OWNER_STRING)) {
		return NFS4_ACL_WHO_OWNER;
	}
	if (0 == strcmp(p, NFS4_ACL_WHO_GROUP_STRING) &&
			strlen(p) == strlen(NFS4_ACL_WHO_GROUP_STRING)) {
		return NFS4_ACL_WHO_GROUP;
	}
	if (0 == strcmp(p, NFS4_ACL_WHO_EVERYONE_STRING) &&
			strlen(p) == strlen(NFS4_ACL_WHO_EVERYONE_STRING)) {
		return NFS4_ACL_WHO_EVERYONE;
	}
	return NFS4_ACL_WHO_NAMED;
}


