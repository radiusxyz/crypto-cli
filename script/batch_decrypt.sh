#!/bin/sh --
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

beginTime=$(date +%s%N)

use_thread=true

echo "### Start decryption batch###"
echo "- Use thread: $use_thread"

$SCRIPTPATH/../target/debug/crypto_cli --action-type batch_decrypt --batch-file-path $SCRIPTPATH/data/batch_decryption_info.data --use-thread $use_thread > $SCRIPTPATH/data/result.txt

endTime=$(date +%s%N) 
elapsed=`echo "($endTime - $beginTime) / 1000000" | bc` 
elapsedSec=`echo "scale=6;$elapsed / 1000" | bc | awk '{printf "%.6f", $1}'` 
echo TOTAL: $elapsedSec sec
echo ""

cat $SCRIPTPATH/data/result.txt


