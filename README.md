# The DKSAP implementation for the Polkadot ecosystem

### Overview

Public ledgers are generally seen as “pseudo-anonymous” as addresses can be linked to one person although that person’s identity is unknown to the public. However, by combining this info with other data it is possible to discover the real-world identity behind the address. Many individuals and companies prefer to have an additional layer of security to keep their privacy. That’s where Dual-Key Stealth Address Protocol(DKSAP) comes to play.

This project was funded by the Web3 Foundation Grants Program.

* [Proposal: Dual-Key Stealth Address Protocol](https://github.com/w3f/Grants-Program/pull/997)
* [Milestone Delivery: Dual-Key Stealth Address Protocol](https://github.com/w3f/Grant-Milestone-Delivery/pull/504)


### Algorithm
The first full working implementation of DKSAP(Dual-Key Stealth Address Protocol) was announced by a developer known as rynomster/sdcoin in 2014 for ShadowSend, a capable, efficient and decentralized anonymous wallet solution. The DKSAP has been implemented in many cryptocurrency systems since then, including Monero, Samourai Wallet, and TokenPay, just to name a few. The protocol takes advantage of two pairs of cryptographic keys, namely a ‘scan key’ pair and a ‘spend key’ pair, and computes a one-time payment address per transaction, as detailed below:

* The receiver has two private/public key pairs (s, S) and (b, B), where S = s^G and B = b^G are ‘scan public key’ and ‘spend public key’, respectively. Here G is the base point of an elliptic curve group.

* The sender generates an ephemeral key pair (r, R), where R = r^G, and transmits it with the transaction.

* Both the sender and receiver can compute a shared secret c using the ECDH: c = H(r^s^G) = H(r^S) = H(s^R), where H(^) is a cryptographic hash function.

* The sender uses c^G + B as the ephemeral destination address for sending the payment.

* The receiver actively monitors the blockchain and checks whether some transaction has been sent to the purported destination address c^G + B. Depending on whether the wallet is encrypted, the receiver can compute the same destination address in two different ways, i.e., c^G + B = (c + b)^G. If there is a match, the payment can be spent using the corresponding private key c + b. Note that the ephemeral private key c + b can only be computed by the receiver.

In DKSAP, if an auditor or a proxy server exists in the system, the receiver can share the ‘scan private key’ s and the ‘spend public key’ B with the auditor/proxy server so that those entities can scan the blockchain transaction on behalf of the receiver. However, they are not able the compute the ephemeral private key c + b and spend the payment.

### Project Details
This project demonstrates how to build non-fungible tokens with an anonymous owner for the Polkadot ecosystem.

#### How to Play

##### Install
If you are a new talent for Polkadot blockchain or Node.js, please install the environment first.

[Install substrate environment](https://docs.substrate.io/tutorials/get-started/build-local-blockchain/)

[Install Node.js environment](https://nodejs.org/en/download/)

```
# Install project dependencies
npm install -d
```

##### Start the local substrate node
```
./target/release/node-template --dev
```

##### Build contract
```
cargo +nightly contract build
```

##### Test contract 
```
cargo +nightly test
```

##### Deploy contract
Upload compiled contract `erc721/target/ink/erc721.contract` to local node by substrate contracts UI.

[Click me to read more instructions](https://docs.substrate.io/tutorials/smart-contracts/first-smart-contract/#deploy-the-contract)


##### Update contract address
Copy erc721 contract address from substrate contracts UI after contract deployed, open config/default.json, and update `ContractAddress`.

##### Start relayer service
```
node relayer/index.js
```

##### Generate key pairs
```
node client/0-generateKeyPair.js
```

##### Register public keys
```
node client/1-registerScanKey.js
```

##### Mint NFT to Alice
```
node client/2-mintToAlice.js
```

##### Transfer NFT from Alice to Bob
```
node client/3-aliceTransferToBob.js
```

##### Transfer NFT from Bob to Alice
```
node client/4-bobTransferToAlice.js
```

##### Burn NFT
```
node client/5-aliceBurn.js
```

### Future Plans
* Currently, user transactions are sent free of charge by relayer. This is not possible in the production environment, so we need to modify the relayer in the future version. We can add a deposit function to NFT so that users can deposit tokens into the contract, and then transfer the token as a transaction fee to the relayer based on zero-knowledge proof.
* Implement other functions of ERC721, such as approve, transferFrom, getApproved, etc.
