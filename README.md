# bench-slopes

Bench-slopes is simple framework for benchmarking algorithm implementations in different
cryptographic libraries. "bench-slope" tool was 
[originally introduced](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=blob;f=tests/bench-slope.c)
as part of libgcrypt library testing suite. This repository extends bench-slope for use with other crypto 
libraries.

Repository currently has support for following libraries:

- libgcrypt library, https://gnupg.org/software/libgcrypt/index.html
- OpenSSL library, https://www.openssl.org/
- nettle library, http://www.lysator.liu.se/~nisse/nettle/
- Botan library, https://botan.randombit.net/
- Crypto++ Library, https://www.cryptopp.com/

## How it works

Benchmark measures speed of algorithm for different input sizes 16, 32, 48, 64, ..., 4096.
From these data points, 'time per byte' slope is calculated. Since the 'time per byte' result
is taken this way, any call overhead is eliminated from the result. Therefore results are close to
'time/cycle per byte for large buffer' benchmarks seen in other benchmarking tools. 

# Building

## Prerequisites

Following packages are needed for building on Ubuntu 20.10: "automake autoconf pkg-config make gcc g++ 
libgcrypt20-dev libssl-dev nettle-dev libcrypto++-dev libbotan-2-dev".

Package names maybe different on other distributions.

## Compiling

- Run './autogen.sh' script
<pre>
$ ./autogen.sh 
configure.ac:14: installing './compile'
configure.ac:46: installing './config.guess'
configure.ac:46: installing './config.sub'
configure.ac:7: installing './install-sh'
configure.ac:7: installing './missing'
src/Makefile.am: installing './depcomp'
</pre>

- Configure in 'build' directory
<pre>
$ cd build/
build/ $ ../configure
checking for a BSD-compatible install... /usr/bin/install -c
checking whether build environment is sane... yes
checking for a thread-safe mkdir -p... /usr/bin/mkdir -p
checking for gawk... no
checking for mawk... mawk
checking whether make sets $(MAKE)... no
checking whether make supports nested variables... no
checking for gcc... gcc
checking whether the C compiler works... yes
...
checking pkg-config is at least version 0.9.0... yes
checking for OPENSSL... yes
checking build system type... x86_64-pc-linux-gnu
checking host system type... x86_64-pc-linux-gnu
checking for libgcrypt-config... /usr/bin/libgcrypt-config
checking for LIBGCRYPT - version >= 1.8.0... yes (1.8.5)
checking for libgcrypt-config... (cached) /usr/bin/libgcrypt-config
checking for LIBGCRYPT - version >= 1.6.0... yes (1.8.5)
checking for gpg-error-config... /usr/bin/gpg-error-config
checking for gpgrt-config... /usr/bin/gpgrt-config
configure: Use gpgrt-config with /usr/lib/x86_64-linux-gnu as gpg-error-config
checking for GPG Error - version >= 1.0... yes (1.37)
checking for botan... yes
checking for cryptopp... yes
checking that generated files are newer than configure... done
configure: creating ./config.status
config.status: creating Makefile
config.status: creating src/Makefile
config.status: creating config.h
config.status: config.h is unchanged
config.status: executing depfiles commands
</pre>

- Compile with 'make'
<pre>
build/ $ make
make  all-recursive
make[1]: Entering directory '/root/bench-slopes/build'
Making all in src
make[2]: Entering directory '/root/bench-slopes/build/src'
gcc -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT slope.o -MD -MP -MF .deps/slope.Tpo -c -o slope.o ../../src/slope.c
mv -f .deps/slope.Tpo .deps/slope.Po
gcc -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT bench-slope-openssl.o -MD -MP -MF .deps/bench-slope-openssl.Tpo -c -o bench-slope-openssl.o ../../src/bench-slope-openssl.c
mv -f .deps/bench-slope-openssl.Tpo .deps/bench-slope-openssl.Po
gcc  -Wall   -o bench-slope-openssl slope.o bench-slope-openssl.o -lssl -lcrypto 
gcc -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT bench-slope-nettle.o -MD -MP -MF .deps/bench-slope-nettle.Tpo -c -o bench-slope-nettle.o ../../src/bench-slope-nettle.c
mv -f .deps/bench-slope-nettle.Tpo .deps/bench-slope-nettle.Po
gcc  -Wall   -o bench-slope-nettle slope.o bench-slope-nettle.o -lnettle
gcc -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT bench-slope-gcrypt.o -MD -MP -MF .deps/bench-slope-gcrypt.Tpo -c -o bench-slope-gcrypt.o ../../src/bench-slope-gcrypt.c
mv -f .deps/bench-slope-gcrypt.Tpo .deps/bench-slope-gcrypt.Po
gcc  -Wall   -o bench-slope-gcrypt slope.o bench-slope-gcrypt.o -L/usr/lib/x86_64-linux-gnu -lgcrypt -L/usr/lib/x86_64-linux-gnu -lgpg-error 
gcc -DHAVE_CONFIG_H -I. -I../../src -I..    -I/usr//include/botan-2 -Wall -MT bench_slope_botan-slope.o -MD -MP -MF .deps/bench_slope_botan-slope.Tpo -c -o bench_slope_botan-slope.o `test -f 'slope.c' || echo '../../src/'`slope.c
mv -f .deps/bench_slope_botan-slope.Tpo .deps/bench_slope_botan-slope.Po
g++ -DHAVE_CONFIG_H -I. -I../../src -I..    -I/usr//include/botan-2 -Wall -MT bench_slope_botan-bench-slope-botan.o -MD -MP -MF .deps/bench_slope_botan-bench-slope-botan.Tpo -c -o bench_slope_botan-bench-slope-botan.o `test -f 'bench-slope-botan.cpp' || echo '../../src/'`bench-slope-botan.cpp
mv -f .deps/bench_slope_botan-bench-slope-botan.Tpo .deps/bench_slope_botan-bench-slope-botan.Po
g++ -I/usr//include/botan-2 -Wall   -o bench-slope-botan bench_slope_botan-slope.o bench_slope_botan-bench-slope-botan.o -lbotan-2 -fstack-protector -m64 -pthread 
gcc -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT bench_slope_cryptopp-slope.o -MD -MP -MF .deps/bench_slope_cryptopp-slope.Tpo -c -o bench_slope_cryptopp-slope.o `test -f 'slope.c' || echo '../../src/'`slope.c
mv -f .deps/bench_slope_cryptopp-slope.Tpo .deps/bench_slope_cryptopp-slope.Po
g++ -DHAVE_CONFIG_H -I. -I../../src -I..     -Wall -MT bench_slope_cryptopp-bench-slope-cryptopp.o -MD -MP -MF .deps/bench_slope_cryptopp-bench-slope-cryptopp.Tpo -c -o bench_slope_cryptopp-bench-slope-cryptopp.o `test -f 'bench-slope-cryptopp.cpp' || echo '../../src/'`bench-slope-cryptopp.cpp
mv -f .deps/bench_slope_cryptopp-bench-slope-cryptopp.Tpo .deps/bench_slope_cryptopp-bench-slope-cryptopp.Po
g++  -Wall   -o bench-slope-cryptopp bench_slope_cryptopp-slope.o bench_slope_cryptopp-bench-slope-cryptopp.o -lcrypto++ 
cat ../../src/plot_raw_results.sh.in > plot_raw_results.sh
chmod +x plot_raw_results.sh
make[2]: Leaving directory '/root/bench-slopes/build/src'
make[2]: Entering directory '/root/bench-slopes/build'
make[2]: Leaving directory '/root/bench-slopes/build'
make[1]: Leaving directory '/root/bench-slopes/build'
</pre>

## Build binaries

For each configured crypto-library, one bench-slope program is build
in to 'build/src/' directory. These are:

- bench-slope-gcrypt
- bench-slope-openssl
- bench-slope-nettle
- bench-slope-botan
- bench-slope-cryptopp

## Compiling directly with external library

Each program can be compiled also directly. For example:
<pre>
$ gcc -O2 -DHAVE_CLOCK_GETTIME src/slope.c src/bench-slope-gcrypt.c -o bench-slope -I /usr/include -l gcrypt -l gpg-error
$ ./bench-slope 
bench-slope-gcrypt: libgcrypt: 1.10.1
...
</pre>

# Command-line options for bench-slope programs

Command-line help can be shown for each program with --help option:
<pre>
$ src/bench-slope-gcrypt --help
bench-slope-gcrypt: libgcrypt: 1.10.1
usage: bench-slope-gcrypt [options] [hash|mac|cipher|kdf]

 options:
   --cpu-mhz &lt;mhz&gt;           Set CPU speed for calculating cycles
                             per bytes results.  Set as "auto"
                             for auto-detection of CPU speed.
   --repetitions &lt;n&gt;         Use N repetitions (default 64)
   --unaligned               Use unaligned input buffers.
   --csv                     Use CSV output format
   --raw                     Output raw benchmark data in CSV output format
   --machine <name>          Machine name used for raw benchmark files
</pre>

# Running benchmarks

## All algorithms

Without any command-line options, each program runs benchmarks for all algorithms. 

For example, following runs all benchmarks for OpenSSL:
<pre>
$ src/bench-slope-openssl
bench-slope-openssl: OpenSSL 1.1.1f  31 Mar 2020
Hash:
                |  nanosecs/byte   mebibytes/sec   cycles/byte
 MD4            |     0.677 ns/B    1407.8 MiB/s         - c/B
 MD5            |      1.14 ns/B     834.1 MiB/s         - c/B
 BLAKE2b512     |     0.949 ns/B    1005.2 MiB/s         - c/B
 BLAKE2s256     |      1.65 ns/B     576.4 MiB/s         - c/B
...
 SHAKE256       |      1.91 ns/B     499.3 MiB/s         - c/B
                =
Cipher:
 des-ede3       |  nanosecs/byte   mebibytes/sec   cycles/byte
        ECB enc |     25.84 ns/B     36.91 MiB/s         - c/B
        ECB dec |     25.80 ns/B     36.97 MiB/s         - c/B
        CBC enc |     26.62 ns/B     35.83 MiB/s         - c/B
        CBC dec |     25.82 ns/B     36.94 MiB/s         - c/B
...
</pre>

## Specific algorithms

Benchmarks can be limited to specific groups (such as 'hash', 'cipher', etc) and
to specific algorithms.

For example, running only cipher algorithm benchmarks on nettle:
<pre>
$ src/bench-slope-nettle cipher
bench-slope-nettle: Nettle 3.5
Cipher:
 aes128         |  nanosecs/byte   mebibytes/sec   cycles/byte
        ECB enc |      2.34 ns/B     407.9 MiB/s         - c/B
        ECB dec |      2.34 ns/B     408.4 MiB/s         - c/B
        CBC enc |      3.04 ns/B     313.7 MiB/s         - c/B
        CBC dec |      2.41 ns/B     394.9 MiB/s         - c/B
        CTR enc |      2.43 ns/B     393.0 MiB/s         - c/B
...
</pre>

For example, running SHA1 and SHA512 benchmarks on OpenSSL:
<pre>
$ src/bench-slope-openssl hash sha1 sha512
bench-slope-openssl: OpenSSL 1.1.1f  31 Mar 2020
Hash:
                |  nanosecs/byte   mebibytes/sec   cycles/byte
 SHA1           |     0.435 ns/B    2192.5 MiB/s         - c/B
 SHA512         |      1.09 ns/B     877.6 MiB/s         - c/B
</pre>

## CPU Mhz and 'cycles per byte' results, --cpu-mhz <mhz>

If you know clock frequency of the CPU on which benchmarks are run, you can supply
CPU Mhz value with '--cpu-mhz &lt;mhz&gt;' option. With help of this information, bench-slope
will be able to calculate 'cycles per byte' metric for each algorithm. 

Approach of giving fixed &lt;mhz&gt; only works on CPUs with fixed CPU frequency. For CPUs
with dynamic frequency scaling, you can try '--cpu-mhz auto' setting. With auto-setting
bench-slope attempts to detect CPU frequency at the time of each algorithm is run and
use this detected frequency to generate 'cycles per byte' metrics.

CPU frequency detection currently does not work on following architectures:

- PowerPC 8/9
- zSeries

(Detection algorithms fails on above cases since routine depends on 'instruction to
instruction' latency for simple arithmetic operations to be one cycle.)

Running Botan benchmarks on CPU with fixed frequency of 6.0 Ghz:
<pre>
src/bench-slope-cryptopp --cpu-mhz 6000 hash CRC32 MD5
bench-slope-cryptopp: Crypto++ 5.6.5
Hash:
                |  nanosecs/byte   mebibytes/sec   cycles/byte
 CRC32          |      2.12 ns/B     450.8 MiB/s     12.69 c/B
 MD5            |      1.81 ns/B     525.9 MiB/s     10.88 c/B
</pre>

Running libgcrypt benchmarks on CPU with dynamic frequency with auto-detection:

<pre>
$ src/bench-slope-gcrypt --cpu-mhz auto hash sha1 ripemd160
bench-slope-gcrypt: libgcrypt: 1.8.5
Hash:
                |  nanosecs/byte   mebibytes/sec   cycles/byte  auto Mhz
 SHA1           |     0.803 ns/B    1188.0 MiB/s      3.49 c/B    4348.7
 RIPEMD160      |      1.82 ns/B     524.0 MiB/s      7.89 c/B    4336.7
</pre>

## Number of repetitions, --repetitions <n>

Number of repetitions option controls accuracy and time which benchmarks
take to run. Higher number of repetitions generally give more accurate and
repeatable results at expense of greater run time for benchmark.

## Unaligned benchmarking, --unaligned

Unaligned option makes all input buffers to algorithms unaligned. This
allows benchmarking effect of unaligned input to algorithms.

## CSV output, --csv

CSV output option allows outputting benchmarking data in machine friendly
format.

For example:

<pre>
$ src/bench-slope-gcrypt --cpu-mhz auto --csv hash sha1 ripemd160
bench-slope-gcrypt: libgcrypt: 1.8.5
hash,SHA1,,,,0.810,ns/B,1176.8,MiB/s,3.52,c/B,4340.2,Mhz,0.8,Mhz-diff
hash,RIPEMD160,,,,1.82,ns/B,524.7,MiB/s,7.95,c/B,4374.1,Mhz
</pre>

## Raw data mode, --raw

TODO: Describe raw mode, which is completely different from normal mode.
TODO: Describe 'plot_raw_results.sh'

## Machine name, --machine <name>

TODO: Describe (used with --raw)

# License

GNU Lesser General Public License v2.1 or later

see: [LICENSE file](LICENSE)
