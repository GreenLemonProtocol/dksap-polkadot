//! # ERC-721
//!
//! This is a non-fungible token with anonymous owner implementation based on a dual-key stealth address protocol.
//!
//! ## Warning
//!
//! This contract is an *example*. It is neither audited nor endorsed for production use.
//! Do **not** rely on it to keep anything of value secure.
//!
//! ## Overview
//!
//! This contract demonstrates how to build non-fungible tokens with an anonymous owner using ink!.
//!
//! ## Error Handling
//!
//! Any function that modifies the state returns a `Result` type and does not changes the state
//! if the `Error` occurs.
//! The errors are defined as an `enum` type. Any other error or invariant violation
//! triggers a panic and therefore rolls back the transaction.
//!
//! ## Register Scan & Spend Public Key
//!
//! Scan public key register start by calling the `register_public_keys` function.
//! When a token owner wants to transfer ownership of the token,
//! it needs to query the receiver's scan public key through the contract, and then generate an encrypted receiver AccountId.
//!
//! ## Token Management
//!
//! After creating a new token, the owner address inputted by the function caller becomes the owner.
//! A token can be created, transferred, or destroyed.
//!
//! Token owners can assign other accounts for transferring specific tokens on their behalf.
//! It is also possible to authorize an operator (higher rights) for another account to handle tokens.
//!
//! ### Token Creation
//!
//! Token creation start by calling the `mint(&mut self, owner: AccountId, id: u32)` function.
//! The token owner becomes the owner address that is inputted by the function caller. The token ID needs to be specified
//! as the argument on this function call.
//!
//! ### Token Transfer
//!
//! Transfers may be initiated by:
//! - The owner of a token
//! - The approved address of a token
//! - An authorized operator of the current owner of a token
//!
//! The token owner can transfer a token by calling the `transfer` functions..
//! An approved address can make a token transfer by calling the `transfer` function.
//! Operators can transfer tokens on another account's behalf or can approve a token transfer
//! for a different account.
//!
//! ### Token Removal
//!
//! Tokens can be destroyed by burning them. Only the token owner is allowed to burn a token.

// This contract inspired by [erc721 from paritytech](https://github.com/paritytech/ink/tree/master/examples/erc721).

#![cfg_attr(not(feature = "std"), no_std)]
use ink_lang as ink;

#[ink::contract]
pub mod erc721 {
  use ink_prelude::{string::String, string::ToString, vec::Vec};

  use ink_storage::{traits::SpreadAllocate, Mapping};

  use scale::{Decode, Encode};

  /// A token ID.
  pub type TokenId = u32;

  #[ink(storage)]
  #[derive(Default, SpreadAllocate)]
  pub struct Erc721 {
    /// Total supply
    total_supply: u32,
    /// Mapping from alias to scan public key & spend public key.
    public_keys: Mapping<String, (String, String)>,
    /// Mapping from token to owner.
    token_owner: Mapping<TokenId, AccountId>,
    /// Mapping from token to ephemeral public key.
    token_ephemeral: Mapping<TokenId, String>,
    /// Mapping from owner to number of owned token.
    owned_tokens_count: Mapping<AccountId, u32>,
    /// Mapping from token to approvals users.
    token_approvals: Mapping<TokenId, AccountId>,
    /// Mapping from token to nonce, which is an incrementing integer added to a hashed.
    token_nonce: Mapping<TokenId, u32>,
    /// Token Base URI
    base_uri: String,
  }

  #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub enum Error {
    NotOwner,
    NotApproved,
    AliasExists,
    TokenNotFound,
    CannotInsert,
    CannotFetchValue,
    NotAllowed,
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    /// or `A...F`.
    InvalidHexCharacter,
    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    OddLength,
  }

  /// Event emitted when a token transfer occurs.
  #[ink(event)]
  pub struct Transfer {
    #[ink(topic)]
    from: Option<AccountId>,
    #[ink(topic)]
    to: Option<AccountId>,
    #[ink(topic)]
    id: TokenId,
  }

  /// Event emitted when a token approve occurs.
  #[ink(event)]
  pub struct Approval {
    #[ink(topic)]
    from: AccountId,
    #[ink(topic)]
    to: AccountId,
    #[ink(topic)]
    id: TokenId,
  }

  #[ink(impl)]
  impl Erc721 {
    /// Returns a anonymous NFT contract instance with the base_uri given
    ///
    /// # Arguments
    ///
    /// * `base_uri` - Base Uniform Resource Identifier (URI)
    ///
    /// Creates a new ERC-721 token contract.
    #[ink(constructor)]
    pub fn new(base_uri: String) -> Self {
      // This call is required in order to correctly initialize the
      // `Mapping`s of our contract.
      ink_lang::utils::initialize_contract(|contract| Self::new_init(contract, base_uri))
    }

    /// Default initializes the ERC-721 contract with the specified base URI.
    fn new_init(&mut self, base_uri: String) {
      self.base_uri = base_uri;
    }

    /// Returns the base Uniform Resource Identifier (URI)
    ///
    /// Returns the base URI. This will be automatically added as a prefix in tokenURI to each token’s URI, or to the token ID if no specific URI is set for that token ID.
    #[ink(message)]
    pub fn base_uri(&self) -> String {
      self.base_uri.clone()
    }

    /// Returns the Uniform Resource Identifier (URI) for tokenId token.
    #[ink(message)]
    pub fn token_uri(&self, id: TokenId) -> String {
      self.base_uri.clone() + "/" + &id.to_string()
    }

    /// Returns the nonce of the token.
    ///
    /// Every signature signed by the token owner needs to hash the latest token nonce
    #[ink(message)]
    pub fn token_nonce_of(&self, id: TokenId) -> u32 {
      self.token_nonce.get(&id).unwrap_or(0)
    }

    /// Returns the balance of the owner.
    ///
    /// This represents the amount of unique tokens the owner has.
    #[ink(message)]
    pub fn balance_of(&self, owner: AccountId) -> u32 {
      self.balance_of_or_zero(&owner)
    }

    /// Returns the owner of the token.
    #[ink(message)]
    pub fn owner_of(&self, id: TokenId) -> Option<AccountId> {
      self.token_owner.get(&id)
    }

    /// Returns the approved account ID for this token if any.
    #[ink(message)]
    pub fn get_approved(&self, id: TokenId) -> Option<AccountId> {
      self.token_approvals.get(&id)
    }

    /// Approves the account to transfer the specified token on behalf of the caller.
    #[ink(message)]
    pub fn approve(
      &mut self,
      to: AccountId,
      id: TokenId,
      ephemeral_public_key: String,
      signature: String,
    ) -> Result<(), Error> {
      self.approve_for(&to, id, ephemeral_public_key, signature)?;
      Ok(())
    }

    /// Returns the ephemeral public key by NFT id.
    #[ink(message)]
    pub fn ephemeral_public_key_of(&self, id: TokenId) -> Option<String> {
      self.token_ephemeral.get(&id)
    }

    /// Returns the public keys of the alias.
    #[ink(message)]
    pub fn public_keys_of(&self, alias: String) -> Option<(String, String)> {
      self.public_keys.get(&alias)
    }

    /// Returns the toatl supply.
    #[ink(message)]
    pub fn total_supply(&self) -> u32 {
      self.total_supply
    }

    /// Register scan public key
    #[ink(message)]
    pub fn register_public_keys(
      &mut self,
      alias: String,
      scan_public_key: String,
      spend_public_key: String,
    ) -> Result<(), Error> {
      if self.public_keys.contains(&alias) {
        return Err(Error::AliasExists);
      }
      self
        .public_keys
        .insert(&alias, &(scan_public_key, spend_public_key));

      Ok(())
    }

    /// Transfers the token from the caller to the given `AccountId`.
    #[ink(message)]
    pub fn transfer(
      &mut self,
      to: AccountId,
      id: TokenId,
      ephemeral_public_key: String,
      signature: String,
    ) -> Result<(), Error> {
      // hash input params
      let messag_hash = self.hash_message(to, id, ephemeral_public_key.clone());
      // recover signer
      let signer = self.recover_signer(&messag_hash, &signature)?;

      self.transfer_token_from(&signer, &to, id, ephemeral_public_key)?;

      Ok(())
    }

    /// Transfer approved or owned token.
    #[ink(message)]
    pub fn transfer_from(
      &mut self,
      from: AccountId,
      to: AccountId,
      id: TokenId,
      ephemeral_public_key: String,
      signature: String,
    ) -> Result<(), Error> {
      // hash input params
      let messag_hash = self.hash_message(to, id, ephemeral_public_key.clone());
      // recover signer
      let signer = self.recover_signer(&messag_hash, &signature)?;

      if Some(signer) != self.get_approved(id) {
        return Err(Error::NotApproved);
      }

      self.transfer_token_from(&from, &to, id, ephemeral_public_key)?;

      Ok(())
    }

    /// Creates a new token.
    #[ink(message)]
    pub fn mint(&mut self, owner: AccountId, ephemeral_public_key: String) -> Result<(), Error> {
      self.total_supply += 1;
      let id = self.total_supply;

      self.add_token_to(&owner, id)?;
      self.env().emit_event(Transfer {
        from: Some(AccountId::from([0x0; 32])),
        to: Some(owner),
        id,
      });
      self.add_ephemeral_public_key(id, ephemeral_public_key);
      self.token_nonce.insert(id, &1);

      Ok(())
    }

    /// Deletes an existing token. Only the owner can burn the token.
    #[ink(message)]
    pub fn burn(&mut self, id: TokenId, signature: String) -> Result<(), Error> {
      let mut input = Vec::new();
      input.extend(id.to_be_bytes());
      input.extend(self.token_nonce_of(id).to_be_bytes());

      let mut messag_hash: [u8; 32] = [0; 32];
      ink_env::hash_bytes::<ink_env::hash::Keccak256>(&input, &mut messag_hash);

      let signer = self.recover_signer(&messag_hash, &signature)?;

      let owner = self.token_owner.get(&id).ok_or(Error::TokenNotFound)?;
      if owner != signer {
        return Err(Error::NotOwner);
      };

      let count = self
        .owned_tokens_count
        .get(&signer)
        .map(|c| c - 1)
        .ok_or(Error::CannotFetchValue)?;
      self.owned_tokens_count.insert(&signer, &count);
      self.token_owner.remove(&id);
      self.token_nonce.remove(&id);
      self.total_supply -= 1;

      self.env().emit_event(Transfer {
        from: Some(signer),
        to: Some(AccountId::from([0x0; 32])),
        id,
      });

      Ok(())
    }

    /// Hash receiver + NFT id + ephemeral_public_key
    /// return the hashed value
    fn hash_message(&self, to: AccountId, id: TokenId, ephemeral_public_key: String) -> [u8; 32] {
      let mut input = Vec::new();

      // raw message data compose of to + ephemeral_public_key + id
      let to_bytes: [u8; 32] = *to.as_ref();
      let ephemeral_public_key_bytes: [u8; 33] = self
        .hex_decode(&ephemeral_public_key)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
      input.extend(to_bytes.iter());
      input.extend(ephemeral_public_key_bytes.iter());
      input.extend(id.to_be_bytes());
      input.extend(self.token_nonce_of(id).to_be_bytes());

      // use keccka256 to hash the raw message data
      let mut messag_hash: [u8; 32] = [0; 32];
      ink_env::hash_bytes::<ink_env::hash::Keccak256>(&input, &mut messag_hash);

      messag_hash
    }

    /// Recovers the AccountId for given signature and message_hash,
    /// and return the signer
    fn recover_signer(
      &self,
      message_hash: &[u8; 32],
      signature: &String,
    ) -> Result<AccountId, Error> {
      // hex string to bytes
      let signature: [u8; 65] = self
        .hex_decode(signature)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
      // recover the compressed ECDSA public key from signature and message_hash
      let mut recovered_public_key = [0u8; 33];
      ink_env::ecdsa_recover(&signature, message_hash, &mut recovered_public_key).unwrap();

      // encode the compressed ECDSA public key to AccountId
      let mut public_key_hash = [0u8; 32];
      ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&recovered_public_key, &mut public_key_hash);
      let signer = AccountId::from(public_key_hash);

      Ok(signer)
    }

    /// Decodes a hex string into raw bytes.
    ///
    /// Both, upper and lower case characters are valid in the input string and can
    /// even be mixed (e.g. `f9b4ca`, `F9B4CA` and `f9B4Ca` are all valid strings).
    fn hex_decode(&self, hex: &String) -> Result<Vec<u8>, Error> {
      let hex: &[u8] = hex.as_ref();
      if hex.len() % 2 != 0 {
        return Err(Error::OddLength);
      }
      hex
        .chunks(2)
        .enumerate()
        .map(|(_, pair)| Ok(self.val(pair[0])? << 4 | self.val(pair[1])?))
        .collect()
    }

    fn val(&self, c: u8) -> Result<u8, Error> {
      match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(Error::InvalidHexCharacter),
      }
    }

    /// Transfers token `id` `from` the sender to the `to` `AccountId`.
    fn transfer_token_from(
      &mut self,
      from: &AccountId,
      to: &AccountId,
      id: TokenId,
      ephemeral_public_key: String,
    ) -> Result<(), Error> {
      if !self.exists(id) {
        return Err(Error::TokenNotFound);
      };
      if !self.approved_or_owner(Some(*from), id) {
        return Err(Error::NotApproved);
      };

      self.clear_approval(id);
      self.remove_token_from(from, id)?;
      self.add_token_to(to, id)?;
      self.add_ephemeral_public_key(id, ephemeral_public_key);

      // Update token nonce
      let nonce = self
        .token_nonce
        .get(&id)
        .map(|c| c + 1)
        .ok_or(Error::CannotFetchValue)?;
      self.token_nonce.insert(&id, &nonce);

      self.env().emit_event(Transfer {
        from: Some(*from),
        to: Some(*to),
        id,
      });
      Ok(())
    }

    /// Removes token `id` from the owner.
    fn remove_token_from(&mut self, from: &AccountId, id: TokenId) -> Result<(), Error> {
      let Self {
        token_owner,
        owned_tokens_count,
        ..
      } = self;

      if !token_owner.contains(&id) {
        return Err(Error::TokenNotFound);
      }

      let count = owned_tokens_count
        .get(&from)
        .map(|c| c - 1)
        .ok_or(Error::CannotFetchValue)?;
      owned_tokens_count.insert(&from, &count);
      token_owner.remove(&id);

      Ok(())
    }

    /// Adds the token `id` to the `to` AccountID.
    fn add_token_to(&mut self, to: &AccountId, id: TokenId) -> Result<(), Error> {
      let Self {
        token_owner,
        owned_tokens_count,
        ..
      } = self;

      if *to == AccountId::from([0x0; 32]) {
        return Err(Error::NotAllowed);
      };

      let count = owned_tokens_count.get(to).map(|c| c + 1).unwrap_or(1);

      owned_tokens_count.insert(to, &count);
      token_owner.insert(&id, to);

      Ok(())
    }

    /// Adds ephemeral public key to TokenId
    fn add_ephemeral_public_key(&mut self, id: TokenId, ephemeral_public_key: String) {
      if self.token_ephemeral.contains(&id) {
        self.token_ephemeral.remove(&id);
      }

      self.token_ephemeral.insert(&id, &ephemeral_public_key);
    }

    /// Approve the passed `AccountId` to transfer the specified token on behalf of the message's sender.
    fn approve_for(
      &mut self,
      to: &AccountId,
      id: TokenId,
      ephemeral_public_key: String,
      signature: String,
    ) -> Result<(), Error> {
      if !self.exists(id) {
        return Err(Error::TokenNotFound);
      };

      // hash input params
      let messag_hash = self.hash_message(*to, id, ephemeral_public_key.clone());
      // recover signer
      let signer = self.recover_signer(&messag_hash, &signature)?;

      let owner = self.owner_of(id);
      if owner != Some(signer) {
        return Err(Error::NotAllowed);
      };

      if *to == AccountId::from([0x0; 32]) {
        return Err(Error::NotAllowed);
      };

      if self.token_approvals.contains(&id) {
        return Err(Error::CannotInsert);
      } else {
        self.token_approvals.insert(&id, to);
      }

      self.add_ephemeral_public_key(id, ephemeral_public_key);

      // Update token nonce
      let nonce = self
        .token_nonce
        .get(&id)
        .map(|c| c + 1)
        .ok_or(Error::CannotFetchValue)?;
      self.token_nonce.insert(&id, &nonce);

      self.env().emit_event(Approval {
        from: signer,
        to: *to,
        id,
      });

      Ok(())
    }

    /// Removes existing approval from token `id`.
    fn clear_approval(&mut self, id: TokenId) {
      self.token_approvals.remove(&id);
    }

    // Returns the total number of tokens from an account.
    fn balance_of_or_zero(&self, id: &AccountId) -> u32 {
      self.owned_tokens_count.get(id).unwrap_or(0)
    }

    /// Returns true if the `AccountId` `from` is the owner of token `id`
    /// or it has been approved on behalf of the token `id` owner.
    fn approved_or_owner(&self, from: Option<AccountId>, id: TokenId) -> bool {
      let owner = self.owner_of(id);
      from != Some(AccountId::from([0x0; 32]))
        && (from == owner || from == self.token_approvals.get(&id))
    }

    /// Returns true if token `id` exists or false if it does not.
    fn exists(&self, id: TokenId) -> bool {
      self.token_owner.contains(&id)
    }
  }

  /// Unit tests
  #[cfg(test)]
  mod tests {
    // Imports all the definitions from the outer scope so we can use them here.
    use super::*;
    use ink_lang as ink;
    // Because the test environment does not support elliptic curve APIs, public keys and signatures have to be hard-coded for test purposes.
    const ALICE: &str = "Alice";
    const ALICE_SCAN_PUB_KEY: &str =
      "032d822430da92b8f87ccee0872375e15b56622722a90e6427748835b42286838f";
    const ALICE_SPEND_PUB_KEY: &str =
      "0283aed736678d2864d09ce59f487f83051a62d9fa0f9c1ae75858ae1d7185bd12";

    // Alice ephemeral public key.
    const ALICE_EPHEMERAL_PUBLIC_KEY: &str =
      "023283ba9bfc9f689cb4ca88d14734aea6e3bdded740d0e560e9344ab4fe825733";
    const ALICE_ENCRYPTED_ADDRESS_BYTES: [u8; 32] = [
      16, 106, 116, 36, 96, 18, 235, 9, 152, 150, 66, 41, 227, 178, 97, 58, 215, 25, 214, 129, 221,
      230, 182, 93, 103, 15, 31, 51, 86, 33, 248, 192,
    ];

    // Bob ephemeral public key.
    const BOB_EPHEMERAL_PUBLIC_KEY: &str =
      "02c5e1752c5f2d858207407c8d1e0b35a3f078a5d80dd3f109bf9ff0bfebd1f449";
    const BOB_ENCRYPTED_ADDRESS_BYTES: [u8; 32] = [
      163, 107, 29, 40, 120, 48, 34, 216, 17, 150, 100, 98, 245, 18, 117, 135, 100, 170, 65, 66,
      168, 150, 165, 125, 46, 117, 207, 171, 186, 216, 207, 200,
    ];

    // Charlie ephemeral public key.
    const CHARLIE_EPHEMERAL_PUBLIC_KEY: &str =
      "02d6ed2824df9dd354c9343a1daf7a93d1f3bc5b6cfcc4150676b70676b1cadff8";
    const CHARLIE_ENCRYPTED_ADDRESS_BYTES: [u8; 32] = [
      85, 42, 128, 42, 184, 40, 141, 192, 239, 172, 100, 182, 219, 143, 32, 28, 16, 27, 7, 234,
      217, 189, 78, 93, 59, 114, 163, 111, 135, 255, 234, 80,
    ];

    // signature signed by Node.js.
    const ALICE_APPROVE_TO_BOB_SIGNATURE: &str = "cee1d58cc00c64355a7d2bf9b750e6ed0816e9ebbcc2de35aa2acb06178026c62983d2640c027904e31295378aa6750e6a9a1f2d126d49b642819014faa3d1ab01";
    const BOB_TRANSFER_TO_CHARLIE_SIGNATURE: &str = "76caa2e333d969e0ea54edffe62dc9c838666730cd8828d4c845b83cbfdaa88a4baa5dfc657fce0f130df546a2b545dedd81d0e1e5ef847939184018b7376b2400";

    const BASE_URI: &str = "https://raw.githubusercontent.com/GreenLemonProtocol/assets/main/nft";

    #[ink::test]
    fn base_uri_works() {
      // Create a new contract instance.
      let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let nft_id = 1;

      assert_eq!(erc721.token_nonce_of(nft_id), 0);
      // Create token Id 1.
      assert_eq!(erc721.mint(accounts.alice, ephemeral_public_key), Ok(()));

      assert_eq!(erc721.base_uri(), BASE_URI.to_string());
      assert_eq!(erc721.token_uri(nft_id), BASE_URI.to_string() + "/1");
      assert_eq!(erc721.token_nonce_of(nft_id), 1);
    }

    #[ink::test]
    fn register_public_keys() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());

      // Alias Alice does not registered.
      assert_eq!(erc721.public_keys_of(ALICE.to_string().clone()), None);
      // Register scan public key & spend public key for Alice.
      assert_eq!(
        erc721.register_public_keys(
          ALICE.to_string().clone(),
          ALICE_SCAN_PUB_KEY.to_string().clone(),
          ALICE_SPEND_PUB_KEY.to_string().clone()
        ),
        Ok(())
      );
      // The scan&spend public key of Alice should match previously params.
      assert_eq!(
        erc721.public_keys_of(ALICE.to_string().clone()).unwrap(),
        (
          ALICE_SCAN_PUB_KEY.to_string(),
          ALICE_SPEND_PUB_KEY.to_string()
        )
      );

      // Alias Alice cannot register again.
      assert_eq!(
        erc721.register_public_keys(
          ALICE.to_string().clone(),
          ALICE_SCAN_PUB_KEY.to_string().clone(),
          ALICE_SPEND_PUB_KEY.to_string().clone()
        ),
        Err(Error::AliasExists)
      );
    }

    #[ink::test]
    fn mint() {
      let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let nft_id = 1;

      // Token 1 does not exists.
      assert_eq!(erc721.owner_of(1), None);
      assert_eq!(erc721.token_nonce_of(nft_id), 0);

      // Alice does not owns tokens.
      assert_eq!(erc721.balance_of(accounts.alice), 0);

      // Total supply = 0
      assert_eq!(erc721.total_supply(), 0);

      // Create token Id 1.
      assert_eq!(
        erc721.mint(accounts.alice, ephemeral_public_key.clone()),
        Ok(())
      );

      // Total supply = 1
      assert_eq!(erc721.total_supply(), 1);

      // Owner owns 1 token.
      assert_eq!(erc721.balance_of(accounts.alice), nft_id);
      assert_eq!(
        erc721.ephemeral_public_key_of(nft_id),
        Some(ephemeral_public_key.clone())
      );

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(accounts.alice));
      assert_eq!(erc721.token_nonce_of(nft_id), 1);

      // Create token Id 2.
      assert_eq!(erc721.mint(accounts.alice, ephemeral_public_key), Ok(()));

      // Alice balance equal 2
      assert_eq!(erc721.balance_of(accounts.alice), 2);
    }

    #[ink::test]
    fn approve_and_transfer() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let alice_ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let alice_encrypted_address = AccountId::from(ALICE_ENCRYPTED_ADDRESS_BYTES);

      let bob_ephemeral_public_key = BOB_EPHEMERAL_PUBLIC_KEY.to_string();
      let bob_encrypted_address = AccountId::from(BOB_ENCRYPTED_ADDRESS_BYTES);

      let charlie_ephemeral_public_key = CHARLIE_EPHEMERAL_PUBLIC_KEY.to_string();
      let charlie_encrypted_address = AccountId::from(CHARLIE_ENCRYPTED_ADDRESS_BYTES);
      let nft_id = 1;
      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrypted_address, alice_ephemeral_public_key.clone()),
        Ok(())
      );

      // Create token Id 2 for Charlie.
      assert_eq!(
        erc721.mint(
          charlie_encrypted_address,
          charlie_ephemeral_public_key.clone()
        ),
        Ok(())
      );

      // Total supply = 2
      assert_eq!(erc721.total_supply(), 2);

      // Alice owns token 1.
      assert_eq!(erc721.balance_of(alice_encrypted_address), 1);
      assert_eq!(erc721.token_nonce_of(nft_id), 1);

      // Bob transfer token Id 1 should fail
      assert_eq!(
        erc721.transfer(
          charlie_encrypted_address,
          1,
          bob_ephemeral_public_key.clone(),
          BOB_TRANSFER_TO_CHARLIE_SIGNATURE.to_string()
        ),
        Err(Error::NotApproved)
      );

      // Bob approves Alice to transfer token 1.
      assert_eq!(
        erc721.approve(
          alice_encrypted_address,
          2,
          alice_ephemeral_public_key.clone(),
          ALICE_APPROVE_TO_BOB_SIGNATURE.to_string()
        ),
        Err(Error::NotAllowed)
      );

      // Alice approves Bob to transfer token 1.
      assert_eq!(
        erc721.approve(
          bob_encrypted_address,
          nft_id,
          bob_ephemeral_public_key.clone(),
          ALICE_APPROVE_TO_BOB_SIGNATURE.to_string()
        ),
        Ok(())
      );
      assert_eq!(erc721.token_nonce_of(nft_id), 2);

      // Check Bob approved by Alice
      assert_eq!(erc721.get_approved(nft_id), Some(bob_encrypted_address));

      // Bob transfer token Id 1 should work
      assert_eq!(
        erc721.transfer_from(
          alice_encrypted_address,
          charlie_encrypted_address,
          nft_id,
          charlie_ephemeral_public_key,
          BOB_TRANSFER_TO_CHARLIE_SIGNATURE.to_string()
        ),
        Ok(())
      );

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(charlie_encrypted_address));
      assert_eq!(erc721.token_nonce_of(nft_id), 3);
    }

    #[ink::test]
    fn burn() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      // Because the test environment does not support elliptic curve APIs, public keys and signatures have to be hard-coded for test purposes.
      let alice_ephemeral_public_key =
        "03dc431aae4287de9394f619d62db1b778edf2b7cc124b43aa997bd19e873e32a7".to_string();
      let alice_encrtyped_address = AccountId::from([
        196, 250, 116, 227, 97, 67, 187, 105, 255, 166, 192, 240, 230, 161, 59, 203, 103, 129, 38,
        138, 170, 251, 216, 145, 117, 22, 187, 84, 152, 240, 21, 254,
      ]);
      let alice_burn_signature = "a957b9d018192de9786392253a98c6b12cb5f67505fba655350e5f8a67e07c5f72c53d7826191ae4f50e080a869cf7ff0c15a61f4dd73ec88a86166ec33faac900".to_string();
      let nft_id = 1;

      // Try burning a non existent token.
      assert_eq!(
        erc721.burn(1, alice_burn_signature.to_string()),
        Err(Error::TokenNotFound)
      );

      // Total supply = 0
      assert_eq!(erc721.total_supply(), 0);

      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrtyped_address, alice_ephemeral_public_key),
        Ok(())
      );

      // Alice owns token 1.
      assert_eq!(erc721.token_nonce_of(nft_id), 1);
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(alice_encrtyped_address));

      // Try burning this token with a wrong signature.
      assert_eq!(
        erc721.burn(1, ALICE_APPROVE_TO_BOB_SIGNATURE.to_string()),
        Err(Error::NotOwner)
      );

      // Total supply = 1
      assert_eq!(erc721.total_supply(), 1);

      // Burn token Id 1.
      assert_eq!(erc721.burn(1, alice_burn_signature.to_string()), Ok(()));

      // Alice does not owns tokens.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 0);

      // Token Id 1 does not exists.
      assert_eq!(erc721.owner_of(1), None);
      assert_eq!(erc721.token_nonce_of(nft_id), 0);

      // Total supply = 0
      assert_eq!(erc721.total_supply(), 0);
    }
  }
}
