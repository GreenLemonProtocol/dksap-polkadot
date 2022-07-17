import * as crypto from '@polkadot/util-crypto';
import * as secp256k1 from '@noble/secp256k1';
import assert from 'node:assert';

// Pure javascript implementation for Dual-Key Stealth Address Protocol algorithm 
// Algorithm description https://github.com/wuyahuang/dksap-polkadot#algorithm

dksap();
function dksap() {
  // 1. Bob has two private/public key pairs;
  // const scanMnemonic = crypto.mnemonicGenerate();
  const scanMnemonic =
    'shy burden bar connect height try involve glad onion rapid ask express';
  const scanSeed = crypto.mnemonicToMiniSecret(scanMnemonic);
  // const spendMnemonic = crypto.mnemonicGenerate();
  const spendMnemonic =
    'source slim squeeze bacon treat lift rhythm humor cargo topple mistake boss';
  const spendSeed = crypto.mnemonicToMiniSecret(spendMnemonic);

  const scanKeyPair = crypto.secp256k1PairFromSeed(scanSeed);
  const spendKeyPair = crypto.secp256k1PairFromSeed(spendSeed);

  // Bob compute elliptic curve point of scan private key & spend private key
  const s = BigInt('0x' + bytesToHex(scanKeyPair.secretKey));
  const S = secp256k1.Point.fromPrivateKey(s);

  const b = BigInt('0x' + bytesToHex(spendKeyPair.secretKey));
  const B = secp256k1.Point.fromPrivateKey(b);

  // Print Bob's key pair info
  console.log('\n--------- 1. Bob has tow private/public key pairs --------');
  console.log('scan key pair:');
  console.log('   privateKey:', bytesToHex(scanKeyPair.secretKey));
  console.log('   publicKey:', bytesToHex(scanKeyPair.publicKey));
  console.log(
    '   substrate address:',
    crypto.encodeAddress(crypto.blake2AsU8a(scanKeyPair.publicKey))
  );

  console.log('\nspend key pair:');
  console.log('   privateKey:', bytesToHex(spendKeyPair.secretKey));
  console.log('   publicKey:', bytesToHex(spendKeyPair.publicKey));
  console.log(
    '   substrate address:',
    crypto.encodeAddress(crypto.blake2AsU8a(spendKeyPair.publicKey))
  );

  // 2. Alice generate an ephemeral key pair (r, R)
  const aliceMnemonic = crypto.mnemonicGenerate();
  const aliceSeed = crypto.mnemonicToMiniSecret(aliceMnemonic);
  const aliceKeyPair = crypto.secp256k1PairFromSeed(aliceSeed);
  // (r, R)
  const r = BigInt('0x' + bytesToHex(aliceKeyPair.secretKey));
  const R = secp256k1.Point.fromPrivateKey(r);

  // Print ephemeral key pair info
  console.log('\n--------- 2. Alice ephemeral key pair --------');
  console.log('alice ephemeral key pair:');
  console.log('   privateKey:', bytesToHex(aliceKeyPair.secretKey));
  console.log('   publicKey:', bytesToHex(aliceKeyPair.publicKey));
  console.log(
    '   substrate address:',
    crypto.encodeAddress(crypto.blake2AsU8a(aliceKeyPair.publicKey))
  );

  // 3. Compute a shared secret c
  // 3.1 Alice computes a shared secret c = H(S * r)
  const hash_1 = crypto.keccakAsU8a(S.multiply(r).toRawBytes());
  console.log('\n--------- 3. Compute a shared secret c --------');
  console.log(
    '\n--------- 3.1 Alice computes a shared secret c = H(S * r) --------'
  );
  console.log('shared secret c:', Buffer.from(hash_1).toString('hex'));

  // 3.2 Bob computes a shared secret c = H(R * s)
  const hash_2 = crypto.keccakAsU8a(R.multiply(s).toRawBytes());
  console.log(
    '\n--------- 3.2 Bob computes a shared secret c = H(R * s) --------'
  );
  console.log('shared secret c:', Buffer.from(hash_2).toString('hex'));

  // console.log(hash_1, hash_2);
  assert(Buffer.from(hash_1).equals(Buffer.from(hash_2)));
  const c = BigInt('0x' + bytesToHex(hash_1));

  // 4. Alice uses c·G + B as the ephemeral destination address for sending the payment.
  const P = secp256k1.Point.BASE.multiply(c).add(B);
  console.log(
    '\n--------- 4. Alice (c·G + B) generate ephemeral destination address P --------'
  );
  console.log('publicKey(P):', Buffer.from(P.toRawBytes(true)).toString('hex'));
  console.log(
    'substrate address',
    crypto.encodeAddress(crypto.blake2AsU8a(P.toRawBytes(true)))
  );

  // 5. Bob use (c + b) * G computes the same destination address P_B, 
  // and Bob can checks whether some transaction has been sent to this address
  const keyBytes = secp256k1.utils.privateAdd(b, hash_1);
  const newKey = BigInt('0x' + bytesToHex(keyBytes));
  const P_B = secp256k1.Point.BASE.multiply(newKey);
  assert(P.equals(P_B));
  let address = crypto.encodeAddress(crypto.blake2AsU8a(P_B.toRawBytes(true)));

  console.log(
    '\n--------- 5. Bob use (c + b) * G computes the same destination address P_B --------'
  );
  console.log('privateKey(c + b):', bytesToHex(keyBytes));
  console.log('publicKey(P_B)', bytesToHex(P_B.toRawBytes(true)));
  console.log('substrate address', address);

  let tokenId = 1;
  // The tokenId type is u32 in ink!, convert it into bytes 
  function intTobytes(value) {
    var a = new Uint8Array(4);
    a[0] = (value >> 24) & 0xff;
    a[1] = (value >> 16) & 0xff;
    a[2] = (value >> 8) & 0xff;
    a[3] = value & 0xff;
    return a;
  }

  // Raw message data compose of destination + ephemeral_public_key + id
  let destinationAccountId = '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY';
  let destinationBytes = crypto.decodeAddress(destinationAccountId);
  let ephemeralPublicKeyBytes = R.toRawBytes(true);
  let tokenIdBytes = intTobytes(tokenId);
  let messageData = new Uint8Array(
    destinationBytes.length + ephemeralPublicKeyBytes.length + tokenIdBytes.length
  );
  messageData.set(destinationBytes, 0);
  messageData.set(ephemeralPublicKeyBytes, destinationBytes.length);
  messageData.set(tokenIdBytes, destinationBytes.length + ephemeralPublicKeyBytes.length);

  // Polkadot signature and verify signature;
  // Use privateKey(c + b) to sign the messageHash, the messageHash keccak_hash from messageData
  const signatureBytes = crypto.secp256k1Sign(
    messageData,
    { secretKey: keyBytes },
    'keccak'
  );
  const messageHash = crypto.keccakAsHex(messageData).replace('0x', '');
  const signature = bytesToHex(signatureBytes);
  console.log('\n--------- 6. Bob use (c + b) sign message "DKSAP" --------');
  console.log('privateKey(c + b):', bytesToHex(keyBytes));
  console.log('publicKey P: ' + bytesToHex(P.toRawBytes(true)));
  console.log('signature substrate address:', address);
  console.log('signature:', signature);
  console.log('message hash:', messageHash);

  let pk = crypto.secp256k1Expand(P.toRawBytes(true));
  // Verify for given signature is signed by privateKey(c + b)
  const result = crypto.secp256k1Verify(messageData, signatureBytes, pk, 'keccak');
  console.log('signature verify resut:' + result);
  return { address, messageHash, signature };
}

// Convert bytes to hex string
function bytesToHex(buf) {
  return Buffer.from(buf).toString('hex');
}

export { dksap, bytesToHex };
