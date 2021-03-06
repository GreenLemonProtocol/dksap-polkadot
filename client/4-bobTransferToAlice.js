// Import
import axios from 'axios';
import nconf from 'nconf';
import * as crypto from '@polkadot/util-crypto';
import * as secp256k1 from '@noble/secp256k1';
import { contractQuery, generateEncyptedAddress, queryOwnedNFT, bytesToHex, intTobytes } from './util.js';

try {
    // Read constants from config
    nconf.file('./config/default.json');
    const RelayerServiceAddress = nconf.get('RelayerServiceAddress');

    nconf.file('./config/bob.json');
    const bobScanPrivateKey = nconf.get('ScanKeyPair').privateKey;
    const bobSpendPrivateKey = nconf.get('SpendKeyPair').privateKey;

    const receiverAlias = 'Alice';

    // Query first NFT id which owned to Bob's scan private key
    const { tokenId, sharedSecret } = await queryOwnedNFT(bobScanPrivateKey, bobSpendPrivateKey, 1);

    if (tokenId && tokenId > 0) {
        // Query Bob public keys
        const bobPublicKeys = await contractQuery('publicKeysOf', receiverAlias);

        // Convert hex to elliptic curve point
        const scanPublicKeyPoint = secp256k1.Point.fromHex(bobPublicKeys[0]);
        const spendPublicKeyPoint = secp256k1.Point.fromHex(bobPublicKeys[1]);

        // Generate Encrypted address by Alice's public keys
        const { ephemeralPublicKey, destinationAccountId } = await generateEncyptedAddress(scanPublicKeyPoint, spendPublicKeyPoint);

        // Compute private key 
        const keyBytes = secp256k1.utils.privateAdd(bobSpendPrivateKey, sharedSecret);

        // Sign transaction by Alice's spend private key
        let destinationBytes = crypto.decodeAddress(destinationAccountId);
        let ephemeralPublicKeyBytes = ephemeralPublicKey.toRawBytes(true);
        let tokenIdBytes = intTobytes(tokenId);
        let params = new Uint8Array(
            destinationBytes.length + ephemeralPublicKeyBytes.length + tokenIdBytes.length
        );

        // Prepare origin data
        params.set(destinationBytes, 0);
        params.set(ephemeralPublicKeyBytes, destinationBytes.length);
        params.set(tokenIdBytes, destinationBytes.length + ephemeralPublicKeyBytes.length);

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
                action: 'transfer',
                destination: destinationAccountId,
                id: tokenId,
                ephemeral_public_key: bytesToHex(ephemeralPublicKeyBytes),
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
        console.log('Cannot find the NFT that belongs to Bob');
    }
} catch (error) {
    console.log("Send Transaction failed: " + error);
} finally {
    process.exit();
}