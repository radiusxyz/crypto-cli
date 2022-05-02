#!/bin/sh --
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

data=`cat $SCRIPTPATH/data/encryption_info.json`

use_vdf_zkp=true
use_encryption_zkp=true

echo "### Start encryption ###"
echo "- Use vdf zkp: $use_vdf_zkp"
echo "- Use encryption zkp: $use_encryption_zkp"

beginTime=$(date +%s%N)

$SCRIPTPATH/../target/debug/cli --use-vdf-zkp $use_vdf_zkp --use-encryption-zkp $use_encryption_zkp --data "$data" > $SCRIPTPATH/data/decryption_info.json

endTime=$(date +%s%N) 
elapsed=`echo "($endTime - $beginTime) / 1000000" | bc` 
elapsedSec=`echo "scale=6;$elapsed / 1000" | bc | awk '{printf "%.6f", $1}'` 
echo TOTAL: $elapsedSec sec
echo ""

cat $SCRIPTPATH/data/decryption_info.json