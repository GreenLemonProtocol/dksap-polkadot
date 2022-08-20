// Import
import axios from 'axios';
import nconf from 'nconf';
import * as crypto from '@polkadot/util-crypto';
import * as secp256k1 from '@noble/secp256k1';
import { contractQuery, queryOwnedNFT, bytesToHex, intTobytes } from './util.js';

try {
  // Read constants from config
  nconf.file('./config/default.json');
  const RelayerServiceAddress = nconf.get('RelayerServiceAddress');

  nconf.file('./config/alice.json');
  const aliceScanPrivateKey = nconf.get('ScanKeyPair').privateKey;
  const aliceSpendPrivateKey = nconf.get('SpendKeyPair').privateKey;

  // Query first NFT id which owned to Alice's scan private key
  const startTokenId = 1;
  const { tokenId, sharedSecret } = await queryOwnedNFT(aliceScanPrivateKey, aliceSpendPrivateKey, startTokenId);

  if (tokenId && tokenId > 0) {
    const tokenNonce = await contractQuery('tokenNonceOf', tokenId);
    console.log('Current token nonce: ' + tokenNonce);

    // Compute private key 
    const keyBytes = secp256k1.utils.privateAdd(aliceSpendPrivateKey, sharedSecret);

    // Sign transaction by Alice's spend private key
    let tokenIdBytes = intTobytes(tokenId);
    let tokenNonceBytes = intTobytes(tokenNonce);
    let params = new Uint8Array(tokenIdBytes.length + tokenNonceBytes.length);

    // Prepare origin data
    params.set(tokenIdBytes, 0);
    params.set(tokenNonceBytes, tokenIdBytes.length);

    // Hash origin data
    const signatureBytes = crypto.secp256k1Sign(
      params,
      { secretKey: keyBytes },
      'keccak'
    );
    const signature = bytesToHex(signatureBytes);

    // Send transaction through relayer service
    let res = await axios({
      url: RelayerServiceAddress,
      method: 'post',
      timeout: 10000,
      data: {
        action: 'burn',
        id: tokenId,
        signature: signature
      },
      headers: {
        'Content-Type': 'application/json',
      }
    });

    // Check status of relayer repsonse
    if (res.status == 200) {
      console.log('Transaction sent with hash ' + res.data);
    } else {
      console.log('Transaction sent failed, please check your connection to relayer service.');
    }
  } else {
    console.log('Cannot find the NFT that belongs to Alice');
  }
} catch (err) {
  console.log("Send Transaction failed: " + error);
} finally {
  process.exit();
}