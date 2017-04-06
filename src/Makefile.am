bin_PROGRAMS = bench-slope-openssl bench-slope-nettle bench-slope-gcrypt

common_src = slope.h slope.c

bench_slope_openssl_SOURCES = $(common_src) bench-slope-openssl.c
bench_slope_openssl_LDADD = $(OPENSSL_LIBS)

bench_slope_nettle_SOURCES = $(common_src) bench-slope-nettle.c
bench_slope_nettle_LDADD = $(NETTLE_LIBS)

bench_slope_gcrypt_SOURCES = $(common_src) bench-slope-gcrypt.c
bench_slope_gcrypt_LDADD = $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)
