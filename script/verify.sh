#!/bin/sh --
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

data=`cat ${SCRIPTPATH}/data/decryption_info.json`

use_vdf_zkp=true
use_encryption_zkp=false

echo "### Start verify ###"
echo "- Use vdf zkp: $use_vdf_zkp"
echo "- Use encryption zkp: $use_encryption_zkp"

beginTime=$(date +%s%N)

echo "$SCRIPTPATH/../target/debug/crypto_cli --use-vdf-zkp $use_vdf_zkp --use-encryption-zkp $use_encryption_zkp --action-type verify --data "$data" > $SCRIPTPATH/data/result.txt"
$SCRIPTPATH/../target/debug/crypto_cli --use-vdf-zkp $use_vdf_zkp --use-encryption-zkp $use_encryption_zkp --action-type verify --data "$data" > $SCRIPTPATH/data/result.txt

endTime=$(date +%s%N) 
elapsed=`echo "($endTime - $beginTime) / 1000000" | bc` 
elapsedSec=`echo "scale=6;$elapsed / 1000" | bc | awk '{printf "%.6f", $1}'` 
echo "TOTAL: $elapsedSec sec"
echo ""

cat $SCRIPTPATH/data/result.txt