/*  Copyright (c) 2002-2007 The Regents of the University of Michigan.
 *  All rights reserved; all wrongs reversed.
 *
 *  David M. Richter <richterd@citi.umich.edu>
 *  Andy Adamson <andros@citi.umich.edu>
 *  Alexis Mackenzie <allamack@citi.umich.edu>
 *  Alex Soule <soule@umich.edu>
 *  Eva Kramer <eveuh@umich.edu>
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

#define _XOPEN_SOURCE 500
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <attr/xattr.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include <getopt.h>
#include <dirent.h>
#include <ftw.h>
#include "libacl_nfs4.h"

/* Actions */
#define NO_ACTION		0
#define MODIFY_ACTION		1
#define SUBSTITUTE_ACTION	2
#define REMOVE_ACTION		3
#define INSERT_ACTION		4
#define EDIT_ACTION		5

/* Walks */
#define DEFAULT_WALK		0	/* Follow symbolic link args, Skip links in subdirectories */
#define LOGICAL_WALK		1	/* Follow all symbolic links */
#define PHYSICAL_WALK		2	/* Skip all symbolic links */

/* Recursion */
#define NO_RECURSIVE		0
#define YES_RECURSIVE		1

#define MKTMPLATE  		"/tmp/.nfs4_setfacl-tmp-XXXXXX"
#define EDITOR  		"vi"  /* <- evangelism! */
#define u32 u_int32_t

static int apply_action(const char *, const struct stat *, int, struct FTW *);
static int do_apply_action(const char *, const struct stat *);
static int open_editor(const char *);
static struct nfs4_acl* edit_ACL(struct nfs4_acl *, const char *, const struct stat *);
static void __usage(const char *, int);
#define usage()	__usage(basename(argv[0]), is_editfacl)
#define assert_wu_wei(a)	 \
	do { \
		if ((a) != NO_ACTION) { \
			fprintf(stderr, "More than one action specified.\n"); \
			usage(); \
			goto out; \
		} \
	} while (0)

static struct option long_options[] = {
  	{ "add-spec",		1, 0, 'a' },
	{ "add-file",		1, 0, 'A' },
	{ "set-spec",		1, 0, 's' },
	{ "set-file",		1, 0, 'S' },
	{ "remove-spec",	1, 0, 'x' },
	{ "remove-file",	1, 0, 'X' },
	{ "modify",		1, 0, 'm' },
	{ "edit",		0, 0, 'e' },
	{ "test",		0, 0, 't' },
	{ "help",		0, 0, 'h' },
	{ "version",		0, 0, 'v' },
	{ "more-help",		0, 0, 'H' },
	{ "recursive",		0, 0, 'R' },
	{ "physical",		0, 0, 'P' },
	{ "logical",		0, 0, 'L' },
	{ NULL,			0, 0, 0,  },
};

/* need these global so the nftw() callback can use them */
static int action = NO_ACTION;
static int do_recursive = NO_RECURSIVE;
static int walk_type = DEFAULT_WALK;
static int is_editfacl;
static int is_test;
static int ace_index = -1;
static char *mod_string;
static char *from_ace;
static char *to_ace;

/* XXX: things we need to handle:
 *
 *  - we need some sort of 'purge' operation that completely clears an ACL.
 *  - qc like setfacl's default-only/custom-only modes
 *  - maybe qc like setfacl's --mask flag...
 */

int main(int argc, char **argv)
{
	int opt, err = 1;
	int numpaths = 0, curpath = 0;
	char *tmp, **paths = NULL, *path = NULL, *spec_file = NULL;
	FILE *s_fp = NULL;

	if (!strcmp(basename(argv[0]), "nfs4_editfacl")) {
		action = EDIT_ACTION;
		is_editfacl = 1;
	}

	if (argc == 1) {
		usage();
		return err;
	}

	while ((opt = getopt_long(argc, argv, "-:a:A:s:S:x:X:m:ethvHRPL", long_options, NULL)) != -1) {
		switch (opt) {
			case 'a':
				mod_string = optarg;
				goto add;
			case 'A':
				spec_file = optarg;
			add:
				assert_wu_wei(action);
				action = INSERT_ACTION;

				/* run along if no more args (defaults to ace_index 1 == prepend) */
				if (optind == argc)
					break;
				ace_index = strtoul_reals(argv[optind++], 10);
				if (ace_index == ULONG_MAX) {
					/* oops it wasn't an ace_index; reset */
					optind--;
					ace_index = -1;
				} else if (ace_index == 0) {
					fprintf(stderr, "Sorry, valid indices start at '1'.\n");
					goto out;
				}
				break;

			case 's':
				mod_string = optarg;
				goto set;
			case 'S':
				spec_file = optarg;
			set:
				assert_wu_wei(action);
				action = SUBSTITUTE_ACTION;
				break;

			case 'x':
				ace_index = strtoul_reals(optarg, 10);
				if(ace_index == ULONG_MAX)
					mod_string = optarg;
				goto remove;
			case 'X':
				spec_file = optarg;
			remove:
				assert_wu_wei(action);
				action = REMOVE_ACTION;
				break;

			case 'm':
				assert_wu_wei(action);
				action = MODIFY_ACTION;
				if (optind == argc || argv[optind][0] == '-') {
					fprintf(stderr, "Sorry, -m requires 'from_ace' and 'to_ace' arguments.\n");
					goto out;
				}
				from_ace = optarg;
				to_ace = argv[optind++];
				break;

			case 'e':
				assert_wu_wei(action);
				action = EDIT_ACTION;
				break;

			case 't':
				is_test = 1;
				break;

			case 'R':
				do_recursive = YES_RECURSIVE;
				break;

			case 'P':
				if (walk_type != DEFAULT_WALK) {
					fprintf(stderr, "More than one walk type specified\n");
					usage();
					goto out;
				}
				walk_type = PHYSICAL_WALK;
				break;

			case 'L':
				if (walk_type != DEFAULT_WALK) {
					fprintf(stderr, "More than one Walk type specified\n");
					usage();
					goto out;
				}
				walk_type = LOGICAL_WALK;
				break;

			case 'v':
				printf("%s %s\n", basename(argv[0]), VERSION);
				return 0;

			case ':':
				/* missing argument */
				switch (optopt) {
					case 'a':
					case 'A':
						fprintf(stderr, "Sorry, -a requires an 'acl_spec', whilst -A requires a 'spec_file'.\n");
						goto out;
					case 's':
						fprintf(stderr, "Sorry, -s requires an 'acl_spec'.\n");
						goto out;
					case 'S':
						fprintf(stderr, "Sorry, -S requires a 'spec_file'.\n");
						goto out;
					case 'x':
						fprintf(stderr, "Sorry, -x requires either an 'acl_spec' or the specific ace_index of an entry to remove.\n");
						goto out;
					case 'X':
						fprintf(stderr, "Sorry, -X requires a 'spec_file'.\n");
						goto out;
					case 'm':
						fprintf(stderr, "Sorry, -m requires 'from_ace' and 'to_ace' arguments.\n");
						goto out;
					goto out;
				}

			case '\1':
				if (numpaths == 0)
					paths = malloc(sizeof(char *) * (argc - optind + 1));
				paths[numpaths++] = optarg;
				break;

			case 'h':
			case '?':
			default:
				usage();
				return 0;
		}
	}

	if (action == NO_ACTION) {
		fprintf(stderr, "No action specified.\n");
		goto out;
	} else if (numpaths < 1) {
		fprintf(stderr, "No path(s) specified.\n");
		goto out;
	}

	if (spec_file) {
		if (!strcmp(spec_file, "-")) {
			s_fp = stdin;
		} else {
			s_fp = fopen(spec_file, "r");
			if (s_fp == NULL) {
				fprintf(stderr, "Error opening spec file %s: %m\n", spec_file);
				goto out;
			}
		}
		if ((mod_string = nfs4_acl_spec_from_file(s_fp)) == NULL) {
			if (s_fp == stdin)
				spec_file = "(stdin)";
			fprintf(stderr, "Failed to create ACL from contents of 'spec_file' %s.\n", spec_file);
			goto out;
		}
	}

	while (numpaths > curpath) {
		path = paths[curpath++];
		if ((tmp = realpath(path, NULL)) == NULL) {
			fprintf(stderr, "File/directory \"%s\" could not be identified\n", path);
			goto out;
		}
		if (walk_type != PHYSICAL_WALK)
			path = tmp;

		if (do_recursive) {
			err = nftw(path, apply_action, 0, (walk_type == LOGICAL_WALK) ? 0 : FTW_PHYS);
			if (err) {
				fprintf(stderr, "An error occurred during recursive file tree walk.\n");
				goto out;
			}
		} else {
			err = do_apply_action(path, NULL);
			if (err)
				goto out;
		}
		free(tmp);
	}
out:
	if (paths)
		free(paths);
	return err;
}

/* returns 0 on success, nonzero on failure */
static int apply_action(const char *_path, const struct stat *stat, int flag, struct FTW *ftw)
{
	int err;
	char *path = (char *)_path;

	if ((flag & FTW_SL) && (walk_type == PHYSICAL_WALK || ftw->level > 0))
		return 0;

	if (flag == FTW_NS) {
		fprintf(stderr, "An error occurred with stat(2) on %s.\n", path);
		return 1;
	}
	if ((path = realpath(path, NULL)) == NULL) {
		perror(strerror(errno));
		return 1;
	}

	err = do_apply_action(path, stat);
	if (do_recursive && flag == FTW_DNR)
		err = 1; 
	free(path);

	return err;
}

/* returns 0 on success, nonzero on failure */
static int do_apply_action(const char *path, const struct stat *_st)
{
	int err = 0;
	struct nfs4_acl *acl = NULL, *newacl;
	struct stat stats, *st = (struct stat *)_st;

	if (st == NULL) {
		if (stat(path, &stats)) {
			fprintf(stderr, "An error occurred with stat(2) on %s.\n", path);
			goto failed;
		}
		st = &stats;
	}

	if (action == SUBSTITUTE_ACTION)
		acl = nfs4_new_acl(S_ISDIR(st->st_mode));
	else
		acl = nfs4_acl_for_path(path);

	if (acl == NULL) {
		fprintf(stderr, "Failed to instantiate ACL.\n");
		goto failed;
	}

	switch (action) {
	case INSERT_ACTION:
		/* default to prepending */
		if (ace_index < 1)
			ace_index = 1;
		if (nfs4_insert_string_aces(acl, mod_string, (ace_index - 1))) {
			fprintf(stderr, "Failed while inserting ACE(s) (at index %d).\n", ace_index);
			goto failed;
		}
		break;

	case REMOVE_ACTION:
		if (ace_index != -1) {
			/* "ace_index - 1" because we access the ACL zero-based-wise, but the CLI arg is one-based. */
			if ((ace_index - 1) > acl->naces) {
				fprintf(stderr, "Index %u is out of range (%d ACEs in ACL)\n", ace_index, acl->naces);
				goto failed;
			}
			if (nfs4_remove_ace_at(acl, (ace_index - 1))) {
				fprintf(stderr, "Failed to remove ACE at index %u.\n", ace_index);
				goto failed;
			}
		} else if (nfs4_remove_string_aces(acl, mod_string)) {
			fprintf(stderr, "Failed while removing matched ACE(s).\n");
			goto failed;
		}
		break;

	case MODIFY_ACTION:
		if (nfs4_replace_ace_spec(acl, from_ace, to_ace)) {
			fprintf(stderr, "Failed while trying to replace ACE.\n");
			goto failed;
		}
		break;

	case SUBSTITUTE_ACTION:
		if (nfs4_insert_string_aces(acl, mod_string, 0)) {
			fprintf(stderr, "Failed while inserting ACE(s).\n");
			goto failed;
		}
		break;

	case EDIT_ACTION:
		if ((newacl = edit_ACL(acl, path, st)) == NULL)
			goto failed;
		nfs4_free_acl(acl);
		acl = newacl;
		break;
	}

	if (is_test) {
		fprintf(stderr, "## Test mode only - the resulting ACL for \"%s\": \n", path);
		nfs4_print_acl(stdout, acl);
	} else
		err = nfs4_set_acl(acl, path);

out:
	nfs4_free_acl(acl);
	return err;
failed:
	err = 1;
	goto out;
}

/* returns a new struct nfs4_acl on success, or NULL on failure */
static struct nfs4_acl* edit_ACL(struct nfs4_acl *acl, const char *path, const struct stat *stat)
{
	char tmp_name[strlen(MKTMPLATE) + 1];
	int tmp_fd;
	FILE *tmp_fp;
	struct nfs4_acl *newacl = NULL;

	strcpy(tmp_name, MKTMPLATE);
	if ((tmp_fd = mkstemp(tmp_name)) == -1) {
		fprintf(stderr, "Unable to make tempfile \"%s\" for editing.\n", tmp_name);
		return NULL;
	}
	if ((tmp_fp = fdopen(tmp_fd, "w+")) == NULL) {
		fprintf(stderr, "Unable to fdopen tempfile \"%s\" for editing.\n", tmp_name);
		goto out;
	}

	if (stat->st_mode & S_IFDIR)
		fprintf(tmp_fp, "## Editing NFSv4 ACL for directory: %s\n", path);
	else
		fprintf(tmp_fp, "## Editing NFSv4 ACL for file: %s\n", path);
	nfs4_print_acl(tmp_fp, acl);
	rewind(tmp_fp);

	if ((newacl = nfs4_new_acl(S_ISDIR(stat->st_mode))) == NULL) {
		fprintf(stderr, "Failed creating new ACL from tempfile %s. Aborting.\n", tmp_name);
		goto out;
	}
	if (open_editor(tmp_name))
		goto failed;
	if (nfs4_insert_file_aces(newacl, tmp_fp, 0)) {
		fprintf(stderr, "Failed loading ACL from edit tempfile %s. Aborting.\n", tmp_name);
		goto failed;
	}
out:
	unlink(tmp_name);
	return newacl;
failed:
	nfs4_free_acl(newacl);
	newacl = NULL;
	goto out;
}

/* returns 0 on success, nonzero on failure */
static int open_editor(const char *file)
{
	char *editor = NULL;
	char *edargv[3];
	int edpid, w, status, err = 1;
	sigset_t newset, oldset;

	if ((editor = getenv("EDITOR")) == NULL)
		editor = EDITOR;

	edargv[0] = editor;
	edargv[1] = (char *)file;
	edargv[2] = (char *)NULL;
	edpid = fork();

	/* child */
	if (edpid == 0) {
		execvp(edargv[0], edargv);
		fprintf(stderr, "Failed to exec() editor \"%s\".\n", editor);
		return 1;
	} else if (edpid == -1) {
		fprintf(stderr, "Failed to fork() editor \"%s\".\n", editor);
		return 1;
	}

	/* parent */
	sigfillset(&newset);
	sigprocmask(SIG_BLOCK, &newset, &oldset);

	if ((w = waitpid(edpid, &status, 0)) == -1)
		fprintf(stderr, "Failed waitpid()ing for editor \"%s\".\n", editor);
	else if (WIFSTOPPED(status))
		fprintf(stderr, "Editor was stopped by delivery of a signal\n");
	else if (WIFSIGNALED(status))
		fprintf(stderr, "Signalled out of editing\n");
	else if (WIFEXITED(status))
		err = WEXITSTATUS(status);

	sigprocmask(SIG_SETMASK, &oldset, NULL);

	if (err)
		fprintf(stderr, "Editor `%s' did not exit cleanly; changes will not be saved.\n", editor);
	return err;
}

static void __usage(const char *name, int is_ef)
{
	static const char *sfusage = \
	"%s %s -- manipulate NFSv4 file/directory access control lists\n"
	"Usage: %s [OPTIONS] COMMAND file ...\n"
	" .. where COMMAND is one of:\n"
	"   -a acl_spec [index]	 add ACL entries in acl_spec at index (DEFAULT: 1)\n"
	"   -A file [index]	 read ACL entries to add from file\n"
	"   -x acl_spec | index	 remove ACL entries or entry-at-index from ACL\n"
	"   -X file  		 read ACL entries to remove from file\n"
	"   -s acl_spec		 set ACL to acl_spec (replaces existing ACL)\n"
	"   -S file		 read ACL entries to set from file\n"
	"   -e, --edit 		 edit ACL in $EDITOR (DEFAULT: " EDITOR "); save on clean exit\n"
	"   -m from_ace to_ace	 modify in-place: replace 'from_ace' with 'to_ace'\n"
	"   --version		 print version and exit\n"
	"   -?, -h, --help 	 display this text and exit\n"
	"\n"
	" .. and where OPTIONS is any (or none) of:\n"
	"   -R, --recursive	 recursively apply to all files and directories\n"
	"   -L, --logical	 logical walk, follow symbolic links\n"
	"   -P, --physical	 physical walk, do not follow symbolic links\n"
	"   --test	 	 print resulting ACL, do not save changes\n"
	"\n"
	"     NOTE: if \"-\" is given with -A/-X/-S, entries will be read from stdin.\n\n";

	static const char *efusage = \
	"%s %s -- edit NFSv4 file/directory access control lists\n"
	"Usage: %s [OPTIONS] file ...\n"
	" .. where OPTIONS is any (or none) of:\n"
	"   -R, --recursive	 recursively apply to all files and directories\n"
	"   -L, --logical	 logical walk, follow symbolic links\n"
	"   -P, --physical	 physical walk, do not follow symbolic links\n"
	"   --test	 	 print resulting ACL, do not save changes\n";

	fprintf(stderr, is_ef ? efusage : sfusage, name, VERSION, name);
}
