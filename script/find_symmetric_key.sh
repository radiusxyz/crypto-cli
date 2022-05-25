#!/bin/sh --
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

data=`cat ${SCRIPTPATH}/data/decryption_info.json`


echo "### Start find symmetric key ###"

beginTime=$(date +%s%N)

$SCRIPTPATH/../target/debug/crypto_cli --action-type find_symmetric_key --data "$data" > $SCRIPTPATH/data/result.txt

endTime=$(date +%s%N) 
elapsed=`echo "($endTime - $beginTime) / 1000000" | bc` 
elapsedSec=`echo "scale=6;$elapsed / 1000" | bc | awk '{printf "%.6f", $1}'` 
echo "TOTAL: $elapsedSec sec"
echo ""

cat $SCRIPTPATH/data/result.txt