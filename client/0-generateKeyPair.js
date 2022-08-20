import * as crypto from '@polkadot/util-crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { bytesToHex } from './util.js';

// Get current directory
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const parentDir = path.resolve(__dirname, '..');

// Generate config file
const aliceConfigFile = path.resolve(parentDir, './config/alice.json');
const bobConfigFile = path.resolve(parentDir, './config/bob.json');
const charlieConfigFile = path.resolve(parentDir, './config/charlie.json');

(async function () {
  try {
    await generateKeyPairs(aliceConfigFile);
    await generateKeyPairs(bobConfigFile);
    await generateKeyPairs(charlieConfigFile);
  } catch (err) {
    console.error(err);
  } finally {
    process.exit();
  }
})();

async function generateKeyPairs(configFile) {
  try {
    if (fs.existsSync(configFile)) {
      //File exists
      console.log('The key pair file already exists.');
    } else {
      // Generate Scan key pairs
      const scanMnemonic = crypto.mnemonicGenerate();
      const scanSeed = crypto.mnemonicToMiniSecret(scanMnemonic);
      const scanKeyPair = crypto.secp256k1PairFromSeed(scanSeed);

      const scanPrivateKey = bytesToHex(scanKeyPair.secretKey);
      const scanPublicKey = bytesToHex(scanKeyPair.publicKey);

      // Generate Spend key pairs
      const spendMnemonic = crypto.mnemonicGenerate();
      const spendSeed = crypto.mnemonicToMiniSecret(spendMnemonic);
      const spendKeyPair = crypto.secp256k1PairFromSeed(spendSeed);

      const spendPrivateKey = bytesToHex(spendKeyPair.secretKey);
      const spendPublicKey = bytesToHex(spendKeyPair.publicKey);

      // New key pair object
      const keypair = {
        "ScanKeyPair": {
          "privateKey": scanPrivateKey,
          "publicKey": scanPublicKey
        },
        "SpendKeyPair": {
          "privateKey": spendPrivateKey,
          "publicKey": spendPublicKey
        }
      }

      // Save file to config directory
      await fs.writeFileSync(configFile, JSON.stringify(keypair));
      console.log('The key pair has been generated successfully, located in ' + configFile);
    }
  } catch (err) {
    console.error(err)
  }
}