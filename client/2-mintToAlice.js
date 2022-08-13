// Import
import axios from 'axios';
import nconf from 'nconf';
import * as secp256k1 from '@noble/secp256k1';
import { contractQuery, generateEncyptedAddress, bytesToHex } from './util.js';

const aliceAlias = 'Alice';

try {
    // Read constants from config
    nconf.file('./config/default.json');
    const RelayerServiceAddress = nconf.get('RelayerServiceAddress');

    // Query Alice public keys
    const alicePublicKeys = await contractQuery('publicKeysOf', aliceAlias);

    // Convert hex to elliptic curve point
    const scanPublicKeyPoint = secp256k1.Point.fromHex(alicePublicKeys[0]);
    const spendPublicKeyPoint = secp256k1.Point.fromHex(alicePublicKeys[1]);

    // Generate Encrypted address by Alice's public keys
    const { ephemeralPublicKey, owner } = await generateEncyptedAddress(scanPublicKeyPoint, spendPublicKeyPoint);

    // Compress ephemeral public key
    let ephemeralPublicKeyBytes = ephemeralPublicKey.toRawBytes(true);

    // Send transaction through relayer service
    let res = await axios({
        url: RelayerServiceAddress,
        method: 'post',
        timeout: 10000,
        data: {
            action: 'mint',
            owner: owner,
            ephemeral_public_key: bytesToHex(ephemeralPublicKeyBytes)
        },
        headers: {
            'Content-Type': 'application/json',
        }
    });

    // Check status of relayer repsonse
    if (res.status == 200) {
        console.log('Transaction sent with hash ' + res.data);

        // Query owner of new NFT
        const totalSupply = await contractQuery('totalSupply');
        const owner = await contractQuery('ownerOf', totalSupply);

        console.log('New NFT already minted, id = ' + totalSupply);
        console.log('Encrypted destination address: ' + owner);
    } else {
        console.log('Transaction sent failed, please check your connection to relayer service.');
    }
} catch (error) {
    console.log("Send Transaction failed: " + error);
} finally {
    process.exit();
}