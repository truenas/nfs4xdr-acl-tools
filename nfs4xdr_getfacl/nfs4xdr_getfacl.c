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
#include <getopt.h>
#include "libacl_nfs4.h"

static void usage(int);
static void more_help();
static char *execname;

static struct option long_options[] = {
        { "append-id",          0, 0, 'i' },
        { "numeric",            0, 0, 'n' },
        { "verbose",            0, 0, 'v' },
        { "quiet",              0, 0, 'q' },
        { NULL,                 0, 0, 0,  },
};

static int print_acl_path(char *path, int flags, bool quiet)
{
	struct nfs4_acl *acl = NULL;
	char *acl_text = NULL;
	struct stat st;
	int error, trivial;
	bool ok;
	char *aclflags = NULL;

	acl = nfs4_acl_get_file(path);
	if (acl == NULL) {
		return (-1);
	}

	if (!quiet) {
		error = stat(path, &st);
		if (error) {
			nfs4_free_acl(acl);
			return (-1);
		}
		printf("# File: %s\n", path);
		printf("# owner: %d\n", st.st_uid);
		printf("# group: %d\n", st.st_gid);
		printf("# mode: 0o%o\n", st.st_mode);

		error = nfs4_acl_is_trivial_np(acl, &trivial);
		if (error) {
			nfs4_free_acl(acl);
			return (-1);
		}
		ok = nfs4_aclflag_to_text(acl->aclflags4, &aclflags);
		if (!ok) {
			nfs4_free_acl(acl);
			return (-1);
		}
		printf("# trivial_acl: %s\n", trivial == 1 ? "true" : "false");
		printf("# ACL flags: %s\n", aclflags);
		free(aclflags);
	}

	acl_text = _nfs4_acl_to_text_np(acl, 0, flags);
	if (!acl_text) {
		fprintf(stderr, "%s: acl_to_text() failed: %s\n",
			path, strerror(errno));

		nfs4_free_acl(acl);
		return (-1);
	}
	printf("%s", acl_text);
	free(acl_text);
	nfs4_free_acl(acl);
	return (0);
}

int main(int argc, char **argv)
{
	int flags = 0, i, error, opt;
	int carried_error = 0;
	bool quiet = false;

	execname = basename(argv[0]);

        while ((opt = getopt_long(argc, argv, "qinvHh?", long_options, NULL)) != -1) {
                switch (opt) {
		case 'i':
			flags |= ACL_TEXT_APPEND_ID;
			break;
		case 'n':
			flags |= ACL_TEXT_NUMERIC_IDS;
			break;
		case 'v':
			flags |= ACL_TEXT_VERBOSE;
			break;
		case 'q':
			quiet = true;
			break;
		case 'H':
			more_help();
			return 0;
		case 'h':
		case '?':
		default:
			usage(1);
			return 0;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fprintf(stderr, "%s: path not specified.\n", execname);
		usage(0);
		return (1);
	}

	for (i = 0; i < argc; i++) {
		error = print_acl_path(argv[i], flags, quiet);
		if (error) {
			carried_error = error;
		}
	}
	return carried_error;
}

static void usage(int label)
{
	if (label)
		fprintf(stderr, "%s %s -- get NFSv4 file or directory access control lists.\n", execname, VERSION);

	static const char *_usage = \
	"Usage: %s [OPTIONS] [file ...]\n\n"
	"    -i, --append-id     append numerical ids to end of entries containing user or group name\n"
	"    -n, --numeric       display user and group IDs rather than user or group name\n"
	"    -v, --verbose       display access mask and flags in a verbose form\n"
	"    -q, --quiet         do not write commented information about file name and ownersip.\n"
	"    -H,                 display more help\n";

	fprintf(stderr, _usage, execname);
}

static void more_help()
{
	const char *info = \
	"%s %s -- get NFSv4 file or directory access control lists.\n\n"
	"An NFSv4 ACL consists of one or more NFSv4 ACEs, each delimited by commas or whitespace.\n"
	"An NFSv4 ACE is written as a colon-delimited string in one of the following formats:\n"
	"\n"
	"    <principal>:<permissions>:<flags>:<type>:<numerical id>\n"
	"    <principal>:<permissions>:<flags>:<type>\n"
	"\n"
	"    * <principal> - named user or group, or one of: \"owner@\", \"group@\", \"everyone@\"\n"
	"        in case of named users or groups, principal must be preceded with one of the following:\n"
	"        'user:' or 'u:'\n"
	"        'group:' or 'g:'\n\n"
	"        note: numerical user or group IDs may be specified in lieu of user or group name.\n"
	"\n"
	"    * <permissions> - one or more of:\n"
	"        'r'  read-data / list-directory \n"
	"        'w'  write-data / create-file \n"
	"        'p'  append-data / create-subdirectory \n"
	"        'x'  execute \n"
	"        'd'  delete\n"
	"        'D'  delete-child (directories only)\n"
	"        'a'  read-attrs\n"
	"        'A'  write-attrs\n"
	"        'R'  read-named-attrs\n"
	"        'W'  write-named-attrs\n"
	"        'c'  read-ACL\n"
	"        'C'  write-ACL\n"
	"        'o'  write-owner\n"
	"        's'  synchronize\n"
	"\n"
	"    * <flags> - zero or more (depending on <type>) of:\n"
	"        'f'  file-inherit\n"
	"        'd'  directory-inherit\n"
	"        'n'  no-propagate-inherit\n"
	"        'i'  inherit-only\n"
	"        'I'  inherited\n"
	"\n"
	"    * <type> - one of:\n"
	"        'allow'  allow\n"
	"        'deny'  deny\n"
	"\n"
	"For more information and examples, please refer to the nfs4_acl(5) manpage.\n";

	printf(info, execname, VERSION); 
}
