
// Import
import express from 'express';
import bodyParser from 'body-parser';
import { ApiPromise, WsProvider,Keyring } from '@polkadot/api';
import { ContractPromise } from '@polkadot/api-contract';
import fs from 'fs';
import nconf from 'nconf';

const app = express();
const port = 3000;

// Here we are configuring express to use body-parser as middle-ware.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Init Contract and Signer
nconf.file('./config/default.json');

const wsProvider = new WsProvider(nconf.get('WsProvider'));
const api = await ApiPromise.create({ provider: wsProvider });

const metadata = JSON.parse(fs.readFileSync(nconf.get('ContractMetaData')));

// Construct the keyring after the API (crypto has an async init)
const keyring = new Keyring({ type: 'sr25519' });
const relayerAccount = keyring.addFromUri(nconf.get('RelayerAccount'));

console.log('Relayer address:', relayerAccount.address);

const contractAddress = nconf.get('ContractAddress');
const contract = new ContractPromise(api, metadata, contractAddress);

app.get('/', (req, res) => {
  res.send('Hello World.')
});

app.post('/sendTransaction', async (req, res) => {
  console.log();
  console.log('New transaction incoming: ' + new Date());
  const data = req.body;
  try {
    // Format params
    let args = [];
    for (var key in data) {
      if (data.hasOwnProperty(key) && key != 'action') {
        args.push(data[key]);
      }
    }
    console.log('req.body: ');
    console.log(req.body);

    // Sent transaction to contract
    const gasLimit = -1;
    const storageDepositLimit = null;

    const mint = await contract.tx[data['action']]({ storageDepositLimit, gasLimit }, ...args);
    const hash = await mint.signAndSend(relayerAccount);
    const hashToHex = hash.toHex();
    
    console.log('Transaction sent with hash', hashToHex);
    return res.send(hashToHex);
  } catch (error) {
    console.error(error);
    res.status(500).send({
      message: error
    });
  }
});

app.listen(port, () => {
  console.log(`Relayer listening on port ${port}`)
});