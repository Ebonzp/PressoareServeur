#!/bin/sh

CLEAN=$( git status --porcelain . | wc -l )

if [ $CLEAN != 0 ]; then
	echo "Directory has non commited changes. Aborting ..."
	exit 0
fi

git clean -f -d -x
VERSION=$( cat configure.ac  | grep AC_INIT | cut -d "," -f 2 | sed -e "s/^[ ]*\(.*\)[ ]*$/\1/" )
tar --transform "s+^.+pressoare-b2b-server-$VERSION+" --exclude=pressoare-b2b-server-${VERSION}.tar.bz2 --exclude .gitignore -jcvf pressoare-b2b-server-${VERSION}.tar.bz2 . 

