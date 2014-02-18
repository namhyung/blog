#!/bin/sh

mkdir -p tmp
for F in egloos/*; do 
    sed -ne '/<DIV CLASS=POST_BODY>/,/<DIV CLASS=POST_TAIL/p' $F | \
    sed -e '1d' -e '3,$d' | \
    sed -e 's/<br\/>/\n/g' -e 's/&nbsp;/ /g' -e 's/&frasl;/\//g' | \
    sed -e 's/<li>/\n  &/g' -e 's/<\/\?ul>/\n&/g' | \
    sed -e 's/<\/\?div[^>]*>/\n&\n/g' > tmp/`basename $F`
done
