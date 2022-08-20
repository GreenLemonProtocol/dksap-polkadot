// Import
import { ApiPromise, WsProvider } from '@polkadot/api';
import { ContractPromise } from '@polkadot/api-contract';
import fs from 'fs';
import nconf from 'nconf';
import * as crypto from '@polkadot/util-crypto';
import * as secp256k1 from '@noble/secp256k1';

nconf.file('./config/default.json');

// Node connect init
const wsProvider = new WsProvider(nconf.get('WsProvider'));
const api = await ApiPromise.create({ provider: wsProvider });

// Contract instance init
const metadata = JSON.parse(fs.readFileSync(nconf.get('ContractMetaData')));
const contractAddress = nconf.get('ContractAddress');
const contract = new ContractPromise(api, metadata, contractAddress);

/**
   * Query Contract Call Function
   * @param action - contract action name
   * @param args - query params
   */
export async function contractQuery(action, ...args) {
  const { output } = await contract.query[action](contractAddress, { gasLimit: -1 }, ...args);
  return output.toHuman();
}

/**
   * Generate encrypted address by scan public key & spend public key
   * @param scanPublicKeyPoint - elliptic curve point of scan public key
   * @param spendPublicKeyPoint - elliptic curve point of spend public key
   */
export async function generateEncyptedAddress(scanPublicKeyPoint, spendPublicKeyPoint) {
  // Generate ephemeral key pair
  const mnemonic = crypto.mnemonicGenerate();
  const seed = crypto.mnemonicToMiniSecret(mnemonic);
  const keyPair = crypto.secp256k1PairFromSeed(seed);
  // (r, R)
  const ephemeralPrivateKey = BigInt('0x' + bytesToHex(keyPair.secretKey));
  const ephemeralPublicKey = secp256k1.Point.fromPrivateKey(ephemeralPrivateKey);

  // Compute a shared secret c
  const sharedSecret = crypto.keccakAsU8a(scanPublicKeyPoint.multiply(ephemeralPrivateKey).toRawBytes());
  const cToBigInt = BigInt('0x' + bytesToHex(sharedSecret));

  // Compute encrypted Bob address
  const P = secp256k1.Point.BASE.multiply(cToBigInt).add(spendPublicKeyPoint);
  const PToU8a = crypto.blake2AsU8a((P.toRawBytes(true)));
  // console.log('ephemeralPublicKey: ' + bytesToHex(ephemeralPublicKey.toRawBytes(true)));
  // console.log('encrypted address:');
  // console.log(PToU8a);

  // Convert to substrate address format
  const owner = crypto.encodeAddress(PToU8a);

  return { ephemeralPublicKey, owner };
}

/**
   * Query NFT that owned to scan private key, and if encrypted address matched, this function returns token id, shared secret, encrypted address
   * @param scanPrivateKey - scan private key
   * @param spendPrivateKey - spend private key
   * @param tokenId - current NFT id
   */
export async function queryOwnedNFT(scanPrivateKey, spendPrivateKey, tokenId) {
  console.log('Scanning NFT id: ' + tokenId);

  if (!tokenId) {
    tokenId = 1;
  }
  const s = BigInt('0x' + scanPrivateKey);
  const b = BigInt('0x' + spendPrivateKey);

  // Query ephemeral public key
  const ephemeralPublicKey = await contractQuery('ephemeralPublicKeyOf', tokenId);

  if (ephemeralPublicKey) {
    const R = secp256k1.Point.fromHex(ephemeralPublicKey);

    // Compute shared secret key
    const sharedSecret = crypto.keccakAsU8a(R.multiply(s).toRawBytes());

    // Compute private key
    const keyBytes = secp256k1.utils.privateAdd(b, sharedSecret);
    const newKey = BigInt('0x' + bytesToHex(keyBytes));

    // Compute public key by private key
    const P = secp256k1.Point.BASE.multiply(newKey);

    // Convert to substrate address format
    const substrateAddress = crypto.encodeAddress(crypto.blake2AsU8a(P.toRawBytes(true)));
    const ownerOnChain = await contractQuery('ownerOf', tokenId);

    // Query get_approved of contract
    const approvedOnChain = await contractQuery('getApproved', tokenId);
    // console.log(substrateAddress);

    // Detect owner of NFT equal to substrateAddress
    if (ownerOnChain == substrateAddress || approvedOnChain == substrateAddress) {
      console.log('Match is successful, NFT id ' + tokenId + ' belongs to current scanPrivateKey ' + scanPrivateKey);
      return { tokenId, sharedSecret, P };
    } else {
      console.log('Match failed');
      return await queryOwnedNFT(scanPrivateKey, spendPrivateKey, ++tokenId);
    }
  } else {
    // Not found nft owned by scanPrivateKey
    return 0;
  }
}

/**
   * Convert bytes to hex
   * @param bytes - bytes object
   */
export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

/**
   * Convert integer to bytes
   * @param integer - bytes object
   */
export function intTobytes(integer) {
  var bytes = new Uint8Array(4);
  bytes[0] = (integer >> 24) & 0xff;
  bytes[1] = (integer >> 16) & 0xff;
  bytes[2] = (integer >> 8) & 0xff;
  bytes[3] = integer & 0xff;
  return bytes;
}
