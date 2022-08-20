// Import
import axios from 'axios';
import nconf from 'nconf';
import { contractQuery } from './util.js';

// Read constants from config
// Query Relayer address
nconf.file('./config/default.json');
const RelayerServiceAddress = nconf.get('RelayerServiceAddress');

// Query Alice key pair
nconf.file('./config/alice.json');
const aliceScanKeyPair = nconf.get("ScanKeyPair");
const aliceSpendKeyPair = nconf.get("SpendKeyPair");

// Query Bob key pair
nconf.file('./config/bob.json');
const bobScanKeyPair = nconf.get("ScanKeyPair");
const bobSpendKeyPair = nconf.get("SpendKeyPair");

// Query Charlie key pair
nconf.file('./config/charlie.json');
const charlieScanKeyPair = nconf.get("ScanKeyPair");
const charlieSpendKeyPair = nconf.get("SpendKeyPair");

// Start register process
(async function () {
  try {
    await registerScanPublicKey('Alice', aliceScanKeyPair.publicKey, aliceSpendKeyPair.publicKey);
    await registerScanPublicKey('Bob', bobScanKeyPair.publicKey, bobSpendKeyPair.publicKey);
    await registerScanPublicKey('Charlie', charlieScanKeyPair.publicKey, charlieSpendKeyPair.publicKey);
  } catch (err) {
    console.error(err);
  } finally {
    process.exit();
  }
})();

/**
   * Register scan public key and spend public to contract
   * @param alias - alias name
   * @param scanPublicKey - scan public key
   * @param spendPublicKey - spend public key
   */
async function registerScanPublicKey(alias, scanPublicKey, spendPublicKey) {
  try {
    // Query current alias record
    let aliasRecord = await contractQuery('publicKeysOf', alias);

    if (!aliasRecord) {
      // Send transaction through relayer service
      let res = await axios({
        url: RelayerServiceAddress,
        method: 'post',
        timeout: 10000,
        data: {
          action: 'registerPublicKeys',
          alias: alias,
          scanPublicKey: scanPublicKey,
          spendPublicKey: spendPublicKey
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
      console.log('Public key of ' + alias + ' is already exists');
      console.log(aliasRecord);
    }
    console.log();
  } catch (error) {
    console.log("Send Transaction failed: " + error);
  };
}