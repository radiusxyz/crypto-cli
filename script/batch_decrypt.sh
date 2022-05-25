#!/bin/sh --
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

beginTime=$(date +%s%N)

use_vdf_zkp=false
use_encryption_zkp=false

echo "### Start decryption batch###"
echo "- Use vdf zkp: $use_vdf_zkp"
echo "- Use encryption zkp: $use_encryption_zkp"

$SCRIPTPATH/../target/debug/crypto_cli --use-vdf-zkp $use_vdf_zkp --use-encryption-zkp $use_encryption_zkp  --action-type batch_decrypt --batch-file-path $SCRIPTPATH/data/batch_decryption_info.data --use-thread true > $SCRIPTPATH/data/result.txt

endTime=$(date +%s%N) 
elapsed=`echo "($endTime - $beginTime) / 1000000" | bc` 
elapsedSec=`echo "scale=6;$elapsed / 1000" | bc | awk '{printf "%.6f", $1}'` 
echo TOTAL: $elapsedSec sec
echo ""

cat $SCRIPTPATH/data/result.txt


