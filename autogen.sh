#!/bin/sh

aclocal && autoheader && automake --add-missing && autoconf && ( mkdir build 2>/dev/null || true )
