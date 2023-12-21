#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(bench-slopes, 0.1, jussi.kivilinna@iki.fi)
AC_CONFIG_SRCDIR([src/slope.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

if test "$CFLAGS" = "" ; then
    CFLAGS="-O2"
fi

if test "$CXXFLAGS" = "" ; then
    CXXFLAGS="-O2"
fi

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
AC_CHECK_FUNCS([dlsym])

#
# Check whether the compiler supports inline assembly memory barrier.
#
AC_CACHE_CHECK([whether inline assembly memory barrier is supported],
    [bs_cv_have_asm_volatile_memory],
    [bs_cv_have_asm_volatile_memory=no
    AC_COMPILE_IFELSE([AC_LANG_SOURCE(
      [[void a(int x)
	{
	  asm volatile("":::"memory");
	  asm volatile("":"+r"(x)::"memory"); }]])],
      [bs_cv_have_asm_volatile_memory=yes])])
if test "$bs_cv_have_asm_volatile_memory" = "yes" ; then
   AC_DEFINE(HAVE_GCC_ASM_VOLATILE_MEMORY,1,
     [Define if inline asm memory barrier is supported])
fi

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
AM_PATH_LIBGCRYPT("1.10.0",[AC_DEFINE(HAVE_LIBGCRYPT_1_10,1,"Have libgcrypt >= 1.10")])
AM_PATH_LIBGCRYPT("1.9.0",[AC_DEFINE(HAVE_LIBGCRYPT_1_9,1,"Have libgcrypt >= 1.9")])
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
