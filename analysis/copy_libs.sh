#/bin/bash

ALLLIBS=`cat */*/xmem* | sort -u | cut -d' ' -f4 | grep "^/"`
mkdir -p exelibs

for L in $ALLLIBS; do
  cp $L exelibs/
done
