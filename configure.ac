#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(bench-slopes, 0.1, jussi.kivilinna@iki.fi)
AC_CONFIG_SRCDIR([src/slope.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

CFLAGS="$CFLAGS -Wall"
CXXFLAGS="$CXXFLAGS -Wall"

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_SEARCH_LIBS([clock_gettime],[rt posix4])
AC_CHECK_FUNCS([clock_gettime gettimeofday strdup])

# Check for libnettle
saved_LIBS=$LIBS
LIBS=
AC_CHECK_HEADERS(nettle/nettle-meta.h)
AC_SEARCH_LIBS([nettle_aeads],[nettle],[AC_DEFINE(HAVE_LIBNETTLE,1,"Have libnettle")],
	AC_SEARCH_LIBS([nettle_get_aeads],[nettle],[AC_DEFINE(HAVE_LIBNETTLE,1,"Have libnettle")]))
NETTLE_LIBS=$LIBS
LIBS=$saved_LIBS

# Check for OpenSSL
PKG_CHECK_MODULES([OPENSSL],[openssl >= 0.98],
                  [AC_DEFINE(HAVE_OPENSSL,1,"Have OpenSSL >= 0.98")],
                  [AC_DEFINE(NO_OPENSSL,1,"Does not have OpenSSL >= 0.98")])

# Check for libgcrypt
AM_PATH_LIBGCRYPT("1.8.0",[AC_DEFINE(HAVE_LIBGCRYPT_1_8,1,"Have libgcrypt >= 1.8")])
AM_PATH_LIBGCRYPT("1.6.0",[AC_DEFINE(HAVE_LIBGCRYPT_1_6,1,"Have libgcrypt >= 1.6")])
AM_PATH_GPG_ERROR("1.0")

# Check for botan
PKG_CHECK_MODULES(botan, [botan-2], [AC_DEFINE(HAVE_BOTAN2,1,"Have botan-2")])
BOTAN_LIBS=$botan_LIBS
BOTAN_CFLAGS=$botan_CFLAGS

# Check for Crypto++
PKG_CHECK_MODULES(cryptopp, [libcrypto++], [AC_DEFINE(HAVE_CRYPTOPP,1,"Have Crypto++")])
CRYPTOPP_LIBS=$cryptopp_LIBS
CRYPTOPP_CFLAGS=$cryptopp_CFLAGS

AC_SUBST([NETTLE_LIBS])
AC_SUBST([OPENSSL_LIBS])
AC_SUBST([LIBGCRYPT_LIBS])
AC_SUBST([GPG_ERROR_LIBS])
AC_SUBST([BOTAN_LIBS])
AC_SUBST([BOTAN_CFLAGS])
AC_SUBST([CRYPTOPP_LIBS])
AC_SUBST([CRYPTOPP_CFLAGS])

AC_OUTPUT(Makefile src/Makefile)
