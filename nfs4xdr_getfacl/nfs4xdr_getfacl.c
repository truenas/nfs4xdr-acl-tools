/*  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@citi.umich.edu>
 *  David M. Richter <richterd@citi.umich.edu>
 *  Alexis Mackenzie <allamack@citi.umich.edu>
 *  Alex Soule <soule@umich.edu>
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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include "libacl_nfs4.h"

static void usage(int);
static void more_help();
static char *execname;

int main(int argc, char **argv)
{
	struct nfs4_acl *acl = NULL;
	char *acl_text = NULL;
	struct stat st;
	int res = 1, error, trivial;
	
	execname = basename(argv[0]);

	if (argc < 2) {
		fprintf(stderr, "%s: you must specify a path.\n", execname);
		usage(0);
		goto out;
	} else if (argc > 2) {
		fprintf(stderr, "%s: currently, you may only specify a single path.\n", execname);
		usage(0);
		goto out;
	} else if (!strcmp(argv[1], "-?") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage(1);
		res = 0;
		goto out;
	} else if (!strcmp(argv[1], "-H") || !strcmp(argv[1], "--more-help")) {
		more_help();
		res = 0;
		goto out;
	}
	acl = nfs4_acl_get_file(argv[1]);
	if (acl == NULL) {
		return (1);
	}
	error = stat(argv[1], &st);
	if (error)
		return (1);

	printf("# File: %s\n", argv[1]);
	printf("# owner: %d\n", st.st_uid);
	printf("# group: %d\n", st.st_gid);
	printf("# mode: 0o%o\n", st.st_mode);

	error = nfs4_acl_is_trivial_np(acl, &trivial);
	if (error)
		return (1);

	printf("# trivial_acl: %s\n", trivial == 1 ? "true" : "false");
	printf("# flags: 0x%08x\n", acl->aclflags4);

	acl_text = _nfs4_acl_to_text_np(acl, 0, 0);
	if (!acl_text) {
		fprintf(stderr, "%s: acl_to_text() failed: %s\n",
			argv[1], strerror(errno));
		return (1);
	}
	printf("%s", acl_text);

out:
	return res;
}

static void usage(int label)
{
	if (label)
		fprintf(stderr, "%s %s -- get NFSv4 file or directory access control lists.\n", execname, VERSION);
	fprintf(stderr, "Usage: %s file\n  -H, --more-help\tdisplay ACL format information\n  -?, -h, --help\tdisplay this help text\n", execname);
}

static void more_help()
{
	const char *info = \
	"%s %s -- get NFSv4 file or directory access control lists.\n\n"
	"An NFSv4 ACL consists of one or more NFSv4 ACEs, each delimited by commas or whitespace.\n"
	"An NFSv4 ACE is written as a colon-delimited, 4-field string in the following format:\n"
	"\n"
	"    <type>:<flags>:<principal>:<permissions>\n"
	"\n"
	"    * <type> - one of:\n"
	"        'A'  allow\n"
	"        'D'  deny\n"
	"        'U'  audit\n"
	"        'L'  alarm\n"
	"\n"
	"    * <flags> - zero or more (depending on <type>) of:\n"
	"        'f'  file-inherit\n"
	"        'd'  directory-inherit\n"
	"        'p'  no-propagate-inherit\n"
	"        'i'  inherit-only\n"
	"        'S'  successful-access\n"
	"        'F'  failed-access\n"
	"        'g'  group (denotes that <principal> is a group)\n"
	"\n"
	"    * <principal> - named user or group, or one of: \"OWNER@\", \"GROUP@\", \"EVERYONE@\"\n"
	"\n"
	"    * <permissions> - one or more of:\n"
	"        'r'  read-data / list-directory \n"
	"        'w'  write-data / create-file \n"
	"        'a'  append-data / create-subdirectory \n"
	"        'x'  execute \n"
	"        'd'  delete\n"
	"        'D'  delete-child (directories only)\n"
	"        't'  read-attrs\n"
	"        'T'  write-attrs\n"
	"        'n'  read-named-attrs\n"
	"        'N'  write-named-attrs\n"
	"        'c'  read-ACL\n"
	"        'C'  write-ACL\n"
	"        'o'  write-owner\n"
	"        'y'  synchronize\n"
	"\n"
	"For more information and examples, please refer to the nfs4_acl(5) manpage.\n";

	printf(info, execname, VERSION); 
}
