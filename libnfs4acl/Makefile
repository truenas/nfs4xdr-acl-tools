#
# Copyright (c) 2000-2002 Silicon Graphics, Inc.  All Rights Reserved.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# 
# Further, this software is distributed without any warranty that it is
# free of the rightful claim of any third person regarding infringement
# or the like.  Any license provided herein, whether implied or
# otherwise, applies only to this software file.  Patent licenses, if
# any, provided herein do not apply to combinations of this program with
# other software, or any other product whatsoever.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307,
# USA.
# 
# Contact information: Silicon Graphics, Inc., 1600 Amphitheatre Pkwy,
# Mountain View, CA  94043, or:
# 
# http://www.sgi.com 
# 
# For further information regarding this notice, see: 
# 
# http://oss.sgi.com/projects/GenInfo/SGIGPLNoticeExplan/
#

TOPDIR = ..

LTLDFLAGS += -Wl,--version-script,$(TOPDIR)/exports
include $(TOPDIR)/include/builddefs

LTLIBRARY = libnfs4acl.la
LTLIBS = -lattr
LTLIBS += -lbsd
LTLIBS += -ljansson
LTDEPENDENCIES = $(TOPDIR)/include/nfs4.h

# 3 2 1  ->  .so.2.1.2
# 4 2 1  ->  .so.3.1.2
# 0 1 0  ->  .so.0.0.1
LT_CURRENT = 0
LT_REVISION = 1
LT_AGE = 0


#LIBACL_NFS4_CFILES = \
#	acl_nfs4_get_who.c \
#	acl_nfs4_new.c \
#	acl_nfs4_print.c \
#	acl_nfs4_add_ace.c \
#	acl_nfs4_remove_ace.c \
#	acl_nfs4_copy_acl.c \
#	acl_nfs4_set_who.c \
#	acl_nfs4_free.c \
#	acl_nfs4_utils.c \
#	acl_nfs4_xattr_load.c \
#	acl_nfs4_xattr_pack.c \
#	acl_nfs4_xattr_size.c \
#	acl_nfs4_string2ace.c \
#	acl_nfs4_inheritance.c \
#	nfs4_acl_for_path.c \
#	nfs4_init_acl_from_file.c \
#	nfs4_init_acl_from_string.c \
#	nfs4_remove_string_entries_from_acl.c \
#	nfs4_remove_file_entries_from_acl.c \
#	acl_nfs4_replace_ace.c \
#	__acl_nfs4_string2ace.c \
#	nfs4_print_ace.c \
#	nfs4_print_ace_verbose.c \
#	nfs4_set_acl.c

LIBACL_NFS4_CFILES = \
	acl_nfs4_copy_acl.c \
	acl_nfs4_get_who.c \
	acl_nfs4_set_who.c \
	acl_nfs4_xattr_load.c \
	acl_nfs4_xattr_pack.c \
	acl_nfs4_inheritance.c \
	nfs4_get_acl.c \
	nfs4_acl_spec_from_file.c \
	nfs4_acl_utils.c \
	nfs4_insert_file_aces.c \
	nfs4_insert_string_aces.c \
	nfs4_free_acl.c \
	nfs4_new_acl.c \
	nfs4_new_ace.c \
	nfs4_print_acl.c \
	nfs4_print_acl_json.c \
	nfs4_remove_file_aces.c \
	nfs4_remove_string_aces.c \
	nfs4_set_acl.c \
	nfs41acl_xdr.c \
	nfs4_ace_to_text_bsd.c \
	nfs4_ace_to_json.c \
	nfs4_ace_from_text_bsd.c \
	nfs4_aclflag_text.c \
	nfs4_json_to_acl.c \
	acl_nfs4_support_bsd.c \
	strtoul_reals.c


LIBACL_NFS4_HFILES = libacl_nfs4.h nfs4.h

CFILES = $(LIBACL_NFS4_CFILES)

HFILES = $(LIBACL_NFS4_HFILES)

LCFLAGS = 


default: $(LTLIBRARY) symmy

# i'm not sure how to get the GUI's qmake-stuff to grok libtool; so we cheat!
symmy:
	if ! [ -L libnfs4acl.a ]; then ln -s .libs/libnfs4acl.a . ; fi

include $(BUILDRULES)

install:

install-dev: default
	$(INSTALL_LTLIB_DEV)

install-lib: default
	$(INSTALL_LTLIB)
