/*  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
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
#include "libacl_nfs4.h"

int nfs4_print_ace(FILE *fp, struct nfs4_ace *ace, u32 isdir)
{
	int result;
	char *who, buf[16];

	if (!nfs4_get_ace_type(ace, buf, 0)) {
		printf("Bad Ace Type:%d\n", ace->type);
		goto unexp_failed;
	}
	fprintf(fp, "%s:", buf);
	fprintf(fp, "%s:", nfs4_get_ace_flags(ace, buf));

	/* XXX: this way is unnec. */
	result = acl_nfs4_get_who(ace, NULL, &who);
	if (result != 0)
		goto unexp_failed;
	fprintf(fp, "%s:", who);
	fprintf(fp, "%s\n", nfs4_get_ace_access(ace, buf, isdir));

	free(who);
	return(0);

unexp_failed:
	fprintf(stderr, "Error while printing ACE.\n");
	return(1);
}

