#!/usr/bin/env bash
#
# mayhem/build.sh — builds AgensGraph twice (VPATH builds under mayhem/, both gitignored):
#   build-fuzz/  sanitized + SanCov-instrumented backend, linked into the three in-process harnesses
#                (main.o is linked with its main() renamed, so libFuzzer's main() is used)
#   build-test/  normal-flags build, installed into install-test/, which mayhem/test.sh runs (initdb + psql)
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
BUILD_FUZZ="$SRC/mayhem/build-fuzz"
BUILD_TEST="$SRC/mayhem/build-test"
INSTALL_TEST="$SRC/mayhem/install-test"

# No optional libraries: nothing is fetched or linked beyond libc/libm, so the build is offline by construction.
CONFIGURE_OPTS="--without-readline --without-icu --without-openssl --without-zlib --without-zstd --without-lz4 --without-libxml --without-libcurl --without-liburing"

# 1) Test/oracle build: the project's normal flags, no sanitizers, no -gdwarf-3.
mkdir -p "$BUILD_TEST"
cd "$BUILD_TEST"
if [ ! -f src/Makefile.global ]; then
  CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    "$SRC/configure" $CONFIGURE_OPTS --prefix="$INSTALL_TEST" > configure.log 2>&1 || { tail -30 configure.log; exit 1; }
fi
make -j"$MAYHEM_JOBS" > make.log 2>&1 || { tail -40 make.log; exit 1; }
make install > install.log 2>&1 || { tail -40 install.log; exit 1; }

# 2) Fuzz build: the whole backend sanitized, with SanCov (fuzzer-no-link) so the fuzzed code reports edges.
#    -fno-sanitize=function: PostgreSQL calls through generically typed function pointers (fmgr,
#    node support) by design; with halting UBSan the first call would abort every input.
# ASan fake stacks (use-after-return) move frames to the heap and break PostgreSQL's check_stack_depth()
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fno-sanitize=function -fsanitize-address-use-after-return=never -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
mkdir -p "$BUILD_FUZZ"
cd "$BUILD_FUZZ"
# configure and the build run generated helpers under ASan; leaks there are not findings
export ASAN_OPTIONS=detect_leaks=0
if [ ! -f src/Makefile.global ]; then
  CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS" \
    "$SRC/configure" $CONFIGURE_OPTS --prefix="$BUILD_FUZZ/inst" > configure.log 2>&1 || { tail -30 configure.log; exit 1; }
fi
{ make -j"$MAYHEM_JOBS" -C src/port && make -j"$MAYHEM_JOBS" -C src/common \
  && make -C src/backend generated-headers && make -j"$MAYHEM_JOBS" -C src/backend postgres; } > make.log 2>&1 \
  || { tail -40 make.log; exit 1; }

# main.o's main() would collide with the fuzzing engine's: link a copy with main renamed
# (the rest of main.o, e.g. parse_dispatch_option(), is still needed by the backend).
objcopy --redefine-sym main=pg_server_main src/backend/main/main.o "$BUILD_FUZZ/pg_main_renamed.o"
OBJS=$(cat $(find src/backend -mindepth 2 -maxdepth 2 -name objfiles.txt | sort) src/timezone/objfiles.txt \
  | tr ' ' '\n' | grep -v '^$' | grep -v '^src/backend/main/main\.o$')
OBJS="$OBJS $BUILD_FUZZ/pg_main_renamed.o"
# pg_locale.c's static default_locale is exported (symbol visibility only, no code change) so
# pgfuzz_init() can set the database default locale that InitPostgres() would set (pg_fuzz_common.h)
objcopy --globalize-symbol=default_locale src/backend/utils/adt/pg_locale.o "$BUILD_FUZZ/pg_locale_exported.o"
OBJS=$(echo "$OBJS" | tr ' ' '\n' | sed "s#^src/backend/utils/adt/pg_locale\.o\$#$BUILD_FUZZ/pg_locale_exported.o#" | tr '\n' ' ')
LIBS="src/common/libpgcommon_srv.a src/port/libpgport_srv.a -lm"
INCS="-I$BUILD_FUZZ/src/include -I$SRC/src/include -D_GNU_SOURCE"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BUILD_FUZZ/lsan_off.o"

for h in fuzz_parser fuzz_jsonb fuzz_cypher_funcs; do
  $CC $FUZZ_CFLAGS $INCS -c "$SRC/mayhem/$h.c" -o "$BUILD_FUZZ/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD_FUZZ/$h.o" $OBJS "$BUILD_FUZZ/lsan_off.o" $LIBS -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$BUILD_FUZZ/$h.o" $OBJS "$BUILD_FUZZ/lsan_off.o" $LIBS -o "$SRC/$h-standalone"
done
