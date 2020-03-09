#!/bin/sh

set -eu

fn=$1
src=$2
date=$(git log --max-count=1 --format=%ad --date=format:%FT%TZ $src)

sed -e '/^%%%/,/^%%%/s/\(^date[	 ]*=[	 ]*\).*/\1'$date'/' \
   -e '/^%%%/,/^%%%/s/\(^value[	 ]*=[	 ]*\).*/\1"'$fn'"/' \
    <$src >$src.stamp

if ! diff -u $src $src.stamp
then mv $src.stamp $src
else rm $src.stamp
fi
