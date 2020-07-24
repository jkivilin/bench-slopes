bin_PROGRAMS = bench-slope-openssl bench-slope-nettle bench-slope-gcrypt \
	       bench-slope-botan bench-slope-cryptopp

common_src = slope.h slope.c

bench_slope_openssl_SOURCES = $(common_src) bench-slope-openssl.c
bench_slope_openssl_LDADD = $(OPENSSL_LIBS)

bench_slope_nettle_SOURCES = $(common_src) bench-slope-nettle.c
bench_slope_nettle_LDADD = $(NETTLE_LIBS)

bench_slope_gcrypt_SOURCES = $(common_src) bench-slope-gcrypt.c
bench_slope_gcrypt_LDADD = $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)

bench_slope_botan_SOURCES = $(common_src) bench-slope-botan.cpp
bench_slope_botan_CFLAGS = $(BOTAN_CFLAGS)
bench_slope_botan_CXXFLAGS = $(BOTAN_CFLAGS)
bench_slope_botan_LDADD = $(BOTAN_LIBS)

bench_slope_cryptopp_SOURCES = $(common_src) bench-slope-cryptopp.cpp
bench_slope_cryptopp_CFLAGS = $(CRYPTOPP_CFLAGS)
bench_slope_cryptopp_CXXFLAGS = $(CRYPTOPP_CFLAGS)
bench_slope_cryptopp_LDADD = $(CRYPTOPP_LIBS)

bin_SCRIPTS = plot_raw_results.sh
EXTRA_DIST = plot_raw_results.sh.in
CLEANFILES = $(bin_SCRIPTS)

plot_raw_results.sh: $(srcdir)/plot_raw_results.sh.in
	cat $(srcdir)/plot_raw_results.sh.in > plot_raw_results.sh
	chmod +x plot_raw_results.sh
