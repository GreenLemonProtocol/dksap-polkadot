# The dual-key stealth address protocol for ERC721

### Overview

Public ledgers are generally seen as `pseudo-anonymous` as addresses can be linked to one person although that person’s identity is unknown to the public. However, by combining this info with other data it is possible to discover the real-world identity behind the address. Many individuals and companies prefer to have an additional layer of security to keep their privacy. That’s where Dual-Key Stealth Address Protocol(DKSAP) comes to play.

This project was funded by the Web3 Foundation Grants Program.

* [Proposal: Dual-Key Stealth Address Protocol](https://github.com/w3f/Grants-Program/pull/997)
* [Proposal: Green Lemon Protocol🍋 - An anonymous NFT solution](https://github.com/w3f/Grants-Program/pull/1096)

Medium Articles about Green Lemon Protocol:

* [Green Lemon Protocol — An anonymous NFT solution](https://medium.com/@wuyahuang/green-lemon-protocol-an-anonymous-nft-solution-2fad91cc8f48)

### Algorithm
The first full working implementation of DKSAP(Dual-Key Stealth Address Protocol) was announced by a developer known as rynomster/sdcoin in 2014 for ShadowSend, a capable, efficient and decentralized anonymous wallet solution. The DKSAP has been implemented in many cryptocurrency systems since then, including Monero, Samourai Wallet, and TokenPay, just to name a few. The protocol takes advantage of two pairs of cryptographic keys, namely a `scan key` pair and a `spend key` pair, and computes a one-time encrypted address per transaction, as detailed below:

* The receiver has two private/public key pairs (s, S) and (b, B), where S = s^G and B = b^G are ‘scan public key’ and ‘spend public key’, respectively. Here G is the base point of an elliptic curve group.

* The sender generates an ephemeral key pair (r, R), where R = r^G, and transmits it with the transaction.

* Both the sender and receiver can compute a shared secret c using the ECDH: c = hash(r^s^G) = hash(r^S) = hash(s^R), where hash is a cryptographic hash function.

* The sender uses c^G + B as the ephemeral destination address for sending the token.

* The receiver actively monitors the blockchain and checks whether some transaction has been sent to the purported destination address c^G + B. Depending on whether the wallet is encrypted, the receiver can compute the same destination address in two different ways, i.e., c^G + B = (c + b)^G. If there is a match, the token can be spent using the corresponding private key c + b. Note that the ephemeral private key c + b can only be computed by the receiver.

In DKSAP, if an auditor or a proxy server exists in the system, the receiver can share the `scan private key` s and the `spend public key` B with the auditor/proxy server so that those entities can scan the blockchain transaction on behalf of the receiver. However, they are not able the compute the ephemeral private key c + b and transfer the token.

### Project Details
This project demonstrates how to build non-fungible tokens with an anonymous owner for the Polkadot ecosystem.

#### How to Play

##### Install
If you are a new talent for Polkadot blockchain or Node.js, please install the environment first.

[Download substrate-contracts-node](https://github.com/paritytech/substrate-contracts-node/releases)

[Install Node.js environment](https://nodejs.org/en/download/)

Please [install cargo-contract](https://github.com/paritytech/cargo-contract) before build contracts, because we need to add nightly builds to runtime env & install binaryen in a version >= 99.


```
# Install project dependencies
npm install -d
```

##### Start the local substrate node
```
./substrate-contracts-node --dev
```

##### Build contract
```
cd erc721
cargo +nightly contract build
```

##### Test contract
```
cargo +nightly test
```

##### Generate docs
```
cargo doc --open
```

##### Deploy contract
Upload compiled contract `erc721/target/ink/erc721.contract` to local node by [Substrate Contracts UI](https://contracts-ui.substrate.io/).

##### Base URI for deployment constructor
```
https://raw.githubusercontent.com/GreenLemonProtocol/assets/main/nft
```

[How to deploy contract to local node](https://ink.substrate.io/getting-started/deploy-your-contract/)


##### Update contract address
Copy erc721 contract address from substrate contracts UI after contract deployed, open config/default.json, and update `ContractAddress`.

##### Note: Please back to the project root directory before running the below commands.

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

##### Alice approve Bob to transfer the NFT
```
node client/3-aliceApproveToBob.js
```

##### Bob transfer NFT to Charlie
```
node client/4-bobTransferToCharlie.js
```

##### Charlie transfer NFT to Alice
```
node client/5-charlieTransferToAlice.js
```

##### Alice burn NFT
```
node client/6-aliceBurn.js
```

### Future Plans
* Currently, user transactions are sent free of charge by relayer. This is not possible in the production environment, so we need to modify the relayer in the future version. We can add a deposit function to NFT so that users can deposit tokens into the contract, and then transfer the token as a transaction fee to the relayer based on zero-knowledge proof.

### Demo videos
[Milestone 1](https://www.youtube.com/watch?v=etVIPgOjFNg)
