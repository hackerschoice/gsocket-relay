dnl Process this File with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([gsocket-relay],[1.0.12])
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_TARGET

dnl we use automake
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS(config.h)
AM_PROG_AR

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl
dnl Use these compiler flags if we have gcc.
dnl
if test $ac_cv_c_compiler_gnu = yes; then
  CCOPTS='-O2 -Wall'
  CFLAGS="$CCOPTS $CFLAGS"
fi
test "x$prefix" != "xNONE" || prefix="/usr/local"
test "x$exec_prefix" != "xNONE" || exec_prefix="${prefix}"
trydir_i="${prefix}/include /usr/include"
trydir_l="${prefix}/lib /usr/lib"

if test "${prefix}" != "/usr/local" ; then
	trydir_i="${trydir_i} /usr/local/include"
	trydir_l="${trydir_l} /usr/local/lib"
fi

dnl Try include paths (especially on OSX)
trydir_i="${trydir_i} /usr/local/opt/openssl/include /opt/homebrew/opt/openssl/include"
for xincdir in $trydir_i ; do
	if test ! -d "$xincdir" ; then
		continue;
	fi
	if test x"${INCLUDES}" = x; then
		INCLUDES="-I${xincdir}";
	else
		INCLUDES="$INCLUDES -I${xincdir}";
	fi
done

dnl Try library paths...
trydir_l="${trydir_l} /usr/local/opt/openssl/lib /opt/homebrew/opt/openssl/lib"
for xlibdir in $trydir_l ; do
	if test ! -d "$xlibdir" ; then
		continue;
	fi
	if test -f "${xlibdir}/libssl.a"; then
		STATIC_LIBSSLDIR="${xlibdir}"
	fi
	if test x"${LIBDIR}" = x; then
		LIBDIR="-L${xlibdir}";
	else
		LIBDIR="$LIBDIR -L${xlibdir}";
	fi
done

dnl if --with-gsocket=<dir> is used then try to find include files there
GSOCKET_INC=""
AC_ARG_WITH([gsocket-dir],
	[AS_HELP_STRING([--with-gsocket-dir=DIR],
		[location of gsocket source])],
	[

		if test -f "${withval}/include/gsocket/gsocket.h"; then
			GSOCKET_INC="${withval}/include"
		else
			AC_MSG_ERROR([Not found: $withval/include/gsocket/gsocket.h])
		fi
		LIBGSOCKET_PATH="${withval}/lib"
	],
	[
		dnl try ./gsocket/include
		dnl systemwide installation is the fallback.
		if test -f "${srcdir}/gsocket/include/gsocket/gsocket.h"; then
			GSOCKET_INC="${srcdir}/gsocket/include"
			LIBGSOCKET_PATH="${srcdir}/gsocket/lib"
		fi
	])

if test "x$GSOCKET_INC" != x; then
	dnl Convert path to absolute path (and without .././ shit)
	GSOCKET_INC=$(cd "$GSOCKET_INC"; pwd)
	LIBGSOCKET_PATH=$(cd "$LIBGSOCKET_PATH"; pwd)
	INCLUDES="-I${GSOCKET_INC} $INCLUDES"
	LIBDIR="-L${LIBGSOCKET_PATH} $LIBDIR"
fi

dnl CPPFLAGS="-I${srcdir}/../include ${INCLUDES} $CPPFLAGS"
CPPFLAGS="${INCLUDES} $CPPFLAGS"
LDFLAGS="${LIBDIR} $LDFLAGS"


AC_CHECK_HEADERS(gsocket/gsocket.h)

dnl default perm of .so is 644 but on cygwin must be 755.
dnl PERM_DSO="644"
case "$host" in
*-cygwin*)
	PERM_DSO="755"
	;;
mips-sony-bsd|mips-sony-newsos4)
        AC_DEFINE([NEED_SETPGRP], [1], [Need setpgrp to acquire controlling tty])
	;;
*-*-ultrix*)
        AC_DEFINE([NEED_SETPGRP], [1], [Need setpgrp to acquire controlling tty])
	;;
*-*-darwin*|*-*-*bsd*)
	AC_DEFINE([BSD_SCRIPT], [1], [/usr/bin/script is the bsd variant])
	if test x"$(which ar)" != x'/usr/bin/ar'; then
		ARDIRWARN=1
	fi
	;;
esac

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h sys/endian.h unistd.h string.h netinet/in_systm.h inttypes.h stdint.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T

dnl Checks for library functions.
AC_FUNC_MEMCMP

dnl If size_t is not defined, define size_t to be unsigned. 
AC_TYPE_SIZE_T 
dnl If uid_t is not defined, define uid_t to be int and gid_t to be int.
AC_TYPE_UID_T


AC_CHECK_TYPES(uint128_t,
	[],
	AC_CHECK_TYPES(__uint128_t, [], [AC_ERROR("no 128 bit")])
	[
		#ifdef HAVE_INTTYPES_H
		#  include <inttypes.h>
		#endif

		#ifdef HAVE_STDINT_H
		#  include <stdint.h>
		#endif
	]
)

AC_ARG_ENABLE(static,
[  --enable-static          Compile static binary],
	[STATIC="yes"], [STATIC="no"]
)

dnl OSX does not support static binaries.
dnl At least staticly include OpenSSL libs
if test x"${STATIC}" = xyes; then
	case "$host" in
	*-*-darwin*)
		LDADD_STATIC="${STATIC_LIBSSLDIR}/libssl.a ${STATIC_LIBSSLDIR}/libcrypto.a"
		AC_DEFINE(HAVE_LIBSSL, 1, [Define to 1 if you have the `ssl' library (-lssl)])
		AC_DEFINE(HAVE_LIBCRYPTO, 1, [Define to 1 if you have the `crypto' library (-lcrypto)])
		STATIC_SSL="yes"
		;;
	*)
		CFLAGS_STATIC="-static "
		;;
	esac
fi

AC_CHECK_LIB(socket, socket)
if test x"${STATIC}" = xno; then
  AC_CHECK_LIB(nsl, gethostbyname)
fi
AC_CHECK_LIB(event, event_base_new, [], [AC_MSG_ERROR([libevent not found])])
AC_CHECK_LIB(event_openssl, bufferevent_openssl_socket_new, [], [AC_MSG_ERROR([libevent_openssl not found])])

if test x"$STATIC_SSL" != xyes; then
  AC_CHECK_LIB([crypto], [ENGINE_init], [], [AC_MSG_ERROR([libcrypto not found])])
  AC_CHECK_LIB([ssl], [SSL_new], [], [AC_MSG_ERROR([libssl not found])])
fi

AC_CHECK_LIB(gsocket, GS_new, [], [AC_MSG_ERROR([libgsocket not found. Compile gsocket in ./gsocket or use --with-gsocket-dir.])])
AC_CHECK_FUNCS(gettimeofday memcpy strchr strlcat)

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [Enable debug information.]),
	[debug=true AC_DEFINE(DEBUG, 1, [Debug infos])]
)

AC_ARG_ENABLE([tests],
	AS_HELP_STRING([--enable-tests], [Enable self-tests.]),
	[selftests=true]
)

AS_IF([test x$enable_debug = xyes], [selftests=true])

AS_IF([test x$selftests = xtrue], AC_DEFINE(SELFTESTS, 1, [Self Tests]))

AC_ARG_ENABLE(realprefix,
[ --enable-realprefix      Set real prefix (for dpkg packaging)],
	[REALPREFIX="${enableval}"], [REALPREFIX="${prefix}"]
)

AS_IF([test x$selftests = xtrue], AC_SUBST(PROGRAMS_TEST_LIB, "list-test${EXEEXT} event-test${EXEEXT}"))
AS_IF([test x$selftests = xtrue], AC_SUBST(PROGRAMS_TEST_TOOLS, "packet-test${EXEEXT} readline-test${EXEEXT} console_display-test${EXEEXT} filetransfer-test${EXEEXT}"))

AC_SUBST(LDADD_STATIC, "${LDADD_STATIC}")
AC_SUBST(CFLAGS_STATIC, "${CFLAGS_STATIC}")
AC_SUBST(REALPREFIX, "${REALPREFIX}")
AC_SUBST(LIBGSOCKET_PATH, "${LIBGSOCKET_PATH}")
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

if test x"${STATIC}" = xyes; then
	case "$host" in
	*-*-darwin*)
		echo "
*** OSX does not support static binaries. Creating dynamic binaries ***
*** instead and trying our best to included OpenSSL statically.     ***
"
		;;
	*)
		echo "
********************************** WARNING ***********************************
* Your MUST compile OpenSSL like this:                                       *
* openssl-src>                                                               *
* ./Configure --prefix=\$HOME/usr no-dso no-threads no-shared linux-generic64 * 
* mkdir -p \$HOME/usr && make all install                                     *
* Only then compile gsocket \(using the same --prefix=\):                    *
* gsocket-src> ./configure --prefix=\$HOME/usr --enable-static                *
* gsocket-src> make all install                                              *
* gsocket-src> export PATH=\$HOME/usr/bin:\$PATH                               *
******************************************************************************
"
		;;
	esac
fi

echo "
${PACKAGE_NAME}-${PACKAGE_VERSION} has been configured:

 Host..............: ${host}
 Compiler..........: ${CC}
 Compiler flags....: ${CFLAGS_STATIC}${CFLAGS}
 Preprocessor flags: ${CPPFLAGS}
 Linker flags......: ${LDFLAGS}
 Libraries.........: ${LIBS}

Configuration complete. Now type: make all install"
if test x"${ARDIRWARN}" = x1; then
	AC_MSG_WARN([Build tools seem to be a mix of GNU and Apple.])
	AC_MSG_WARN([Alex, try 'PATH=/usr/bin:\$PATH ./configure'.])
fi

