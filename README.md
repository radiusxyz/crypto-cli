### 0. Build crypto-cli

    `cargo build`

### 1. Encryption

1. Copy the encryption information.

   `cp ./script/data/encryption_info_sample.json ./script/data/encryption_info.json`

2. Modify encryption script option (position: ./script/encrypt.sh)

   --use-vdf-zkp `true/false`
   --use-encryption-zkp `true/false`

3. Run script

   `./script/encrypt.sh`

### 2. Verification

1. Modify verification script option (position: ./script/verify.sh)

   --use-vdf-zkp `true/false`
   --use-encryption-zkp `true/false`

2. Run script

   `./script/encrypt.sh`

### 3. Decryption (single)

1. Run script

   `./script/decrypt.sh`

### 4. Decryption (batch)

1. Make `batch_decryption_info.data`
   `cp ./script/data/batch_decryption_info_example.data ./script/data/batch_decryption_info.data`
2. Modify decryption script option (position: ./script/batch_decrypt.sh)
   --use-thread `true/false`

3. Run script
   `./script/batch_decrypt.sh`
