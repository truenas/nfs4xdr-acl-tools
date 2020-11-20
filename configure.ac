AC_INIT([nfs4xdr-acl-tools], [0.3.3])
AC_CONFIG_HEADER(include/config.h)
AC_PREFIX_DEFAULT(/usr/local)

AC_ARG_ENABLE(shared,
			  [  --enable-shared=[yes/no]  Enable use of shared libraries [default=no]],,
			     enable_shared=no)
AC_SUBST(enable_shared)

AC_PROG_INSTALL
AC_PROG_CC

AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h unistd.h])

AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_SIZE_T

AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([memset strchr])

AC_CHECK_LIB([attr], [getxattr])

AC_PACKAGE_GLOBALS([nfs4aclxdr])
AC_PACKAGE_UTILITIES([nfs4aclxdr])
AC_PACKAGE_NEED_ATTR_XATTR_H
AC_PACKAGE_NEED_GETXATTR_LIBATTR
AC_MANUAL_FORMAT

AC_FUNC_GCC_VISIBILITY
AC_DEFINE([HAVE_VISIBILITY_ATTRIBUTE], [], [Description])

AC_OUTPUT(include/builddefs)
