AC_DEFUN([AC_PACKAGE_NEED_ATTR_XATTR_H],
  [ AC_CHECK_HEADERS([attr/xattr.h])
    if test "$ac_cv_header_attr_xattr_h" != "yes"; then
        echo
        echo 'FATAL ERROR: attr/xattr.h does not exist.'
        echo 'Install the extended attributes (attr) development package.'
        echo 'Alternatively, run "make install-lib" from the attr source.'
        exit 1
    fi
  ])

AC_DEFUN([AC_PACKAGE_NEED_GETXATTR_LIBATTR],
  [ AC_CHECK_LIB(attr, getxattr,, [
        echo
        echo 'FATAL ERROR: could not find a valid Extended Attributes library.'
        echo 'Install the extended attributes (attr) development package.'
        echo 'Alternatively, run "make install-lib" from the attr source.'
        exit 1
    ])
    libattr="-lattr"
    test -f `pwd`/../attr/libattr/libattr.la && \
        libattr="`pwd`/../attr/libattr/libattr.la"
    test -f /usr/lib/libattr.la && libattr="/usr/lib/libattr.la"
    AC_SUBST(libattr)
  ])

AC_DEFUN([AC_PACKAGE_NEED_ATTRGET_LIBATTR],
  [ AC_CHECK_LIB(attr, attr_get,, [
        echo
        echo 'FATAL ERROR: could not find a valid Extended Attributes library.'
        echo 'Install the extended attributes (attr) development package.'
        echo 'Alternatively, run "make install-lib" from the attr source.'
        exit 1
    ])
    libattr="-lattr"
    test -f `pwd`/../attr/libattr/libattr.la && \
        libattr="`pwd`/../attr/libattr/libattr.la"
    test -f /usr/lib/libattr.la && libattr="/usr/lib/libattr.la"
    AC_SUBST(libattr)
  ])
