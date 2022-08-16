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

#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod erc721 {
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
    /// Mapping from AccountId to nonce, which is a number added to a hashed.
    account_nonce: Mapping<AccountId, u32>,
    /// Token Base URI
    base_uri: String,
  }

  #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub enum Error {
    NotOwner,
    NotApproved,
    TokenExists,
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

  impl Erc721 {
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

      Ok(())
    }

    /// Deletes an existing token. Only the owner can burn the token.
    #[ink(message)]
    pub fn burn(&mut self, id: TokenId, signature: String) -> Result<(), Error> {
      let mut input = Vec::new();
      input.extend(id.to_be_bytes());

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

      // use keccka256 to hash the raw message data
      let mut messag_hash: [u8; 32] = [0; 32];
      ink_env::hash_bytes::<ink_env::hash::Keccak256>(&input, &mut messag_hash);

      return messag_hash;
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
      ink_env::ecdsa_recover(&signature, &message_hash, &mut recovered_public_key).unwrap();

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

      if token_owner.contains(&id) {
        return Err(Error::TokenExists);
      }

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
      if !(owner == Some(signer)) {
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
    fn balance_of_or_zero(&self, of: &AccountId) -> u32 {
      self.owned_tokens_count.get(of).unwrap_or(0)
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
    /// Imports all the definitions from the outer scope so we can use them here.
    // Because the test environment does not support elliptic curve APIs, it has to be hard-coded for test purposes.
    use super::*;
    use ink_lang as ink;
    const ALICE: &str = "Alice";
    const ALICE_SCAN_PUB_KEY: &str =
      "03ab1082d409df644256885de6e8df9b60ac185d0cd387dc3b6bdd901bca1bc142";
    const ALICE_SPEND_PUB_KEY: &str =
      "03c71557501541378ea8c35372adb555766d4e0e20bc10116440533cb8d9f45e29";

    // alice ephemeral public key
    const ALICE_EPHEMERAL_PUBLIC_KEY: &str =
      "02b5a762b16e063e90950550b4f0e763c0252ca72c06b749f9333a1e6c4353a097";
    // The alice_encrtyped_address_bytes SS58Address is "5Cu1jWWLfiHjRgnvLDkr1HJQ1ckFWXY5W6k6iUYrSmj7KjMb".
    const ALICE_ENCRTYPED_ADDRESS_BYTES: [u8; 32] = [
      36, 215, 245, 17, 29, 184, 146, 255, 59, 234, 134, 104, 240, 23, 67, 201, 213, 53, 37, 31,
      202, 108, 20, 114, 90, 164, 232, 208, 76, 234, 160, 40,
    ];

    // bob ephemeral public key.
    const BOB_EPHEMERAL_PUBLIC_KEY: &str =
      "02cdb3c440c8a4f0b276b54ada85660ba4d52ba5e4c4b4faa41dbf24f8940e2f1d";
    // The alice_encrtyped_address_bytes SS58Address is "5CgfqZemM4Qjuy3V68xYEKwVXkHUcaFntwRa5s7y3WrGUAdr".
    const BOB_ENCRTYPED_ADDRESS_BYTES: [u8; 32] = [
      27, 110, 9, 174, 212, 73, 235, 126, 22, 14, 5, 39, 57, 236, 197, 196, 33, 60, 122, 60, 243,
      210, 222, 253, 210, 221, 171, 51, 250, 162, 217, 134,
    ];

    // signature signed by Node.js.
    const ALICE_TRANSFER_TO_BOB_SIGNATURE: &str = "8a928342600ef6b6f66720fea96b24509fe4863bdbe15ad70b3272563c8866285e4609d90c3b555a7e3feebbe4f8e1677d55dffbaa530504f1f82c00d8f142a501";
    const ALICE_BURN_SIGNATURE: &str = "f1ef7888110b54243a7c12be25478b7475ccb5a1d6749aeb699a62d7872fa2f6577f4575577e36f656c9df0c85ecbc4f9fc5f2f35b70ebf865e9a2ac9c4e9fee00";

    const BASE_URI: &str = "https://raw.githubusercontent.com/GreenLemonProtocol/assets/main/nft";

    #[ink::test]
    fn base_uri_works() {
      // Create a new contract instance.
      let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let nft_id = 1;

      // Create token Id 1.
      assert_eq!(erc721.mint(accounts.alice, ephemeral_public_key), Ok(()));

      assert_eq!(erc721.base_uri(), BASE_URI.to_string());
      assert_eq!(erc721.token_uri(nft_id), BASE_URI.to_string() + "/1");
    }

    #[ink::test]
    fn register_public_keys_works() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());

      // Alias Alice does not registered.
      assert_eq!(erc721.public_keys_of(ALICE.to_string().clone()), None);
      // Register Alice scan public key & spend public key.
      assert_eq!(
        erc721.register_public_keys(
          ALICE.to_string().clone(),
          ALICE_SCAN_PUB_KEY.to_string().clone(),
          ALICE_SPEND_PUB_KEY.to_string().clone()
        ),
        Ok(())
      );
      // The scan&spend public key of Alice should equal to "alice_public_key".
      assert_eq!(
        erc721.public_keys_of(ALICE.to_string().clone()).unwrap(),
        (
          ALICE_SCAN_PUB_KEY.to_string(),
          ALICE_SPEND_PUB_KEY.to_string()
        )
      );
    }

    #[ink::test]
    fn register_existing_should_fail() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());

      // Register Alice scan&spend public key.
      assert_eq!(
        erc721.register_public_keys(
          ALICE.to_string().clone(),
          ALICE_SCAN_PUB_KEY.to_string().clone(),
          ALICE_SPEND_PUB_KEY.to_string().clone()
        ),
        Ok(())
      );
      // The scan&spend public key of Alice should equal to "alice_public_key".
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
    fn mint_works() {
      let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let nft_id = 1;

      // Token 1 does not exists.
      assert_eq!(erc721.owner_of(1), None);

      // Alice does not owns tokens.
      assert_eq!(erc721.balance_of(accounts.alice), 0);

      // Create token Id 1.
      assert_eq!(erc721.mint(accounts.alice, ephemeral_public_key), Ok(()));

      // Owner owns 1 token.
      assert_eq!(erc721.balance_of(accounts.alice), nft_id);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(accounts.alice));
    }

    #[ink::test]
    fn transfer_works() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let alice_ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let alice_encrtyped_address = AccountId::from(ALICE_ENCRTYPED_ADDRESS_BYTES);

      let bob_ephemeral_public_key = BOB_EPHEMERAL_PUBLIC_KEY.to_string();
      let bob_encrtyped_address = AccountId::from(BOB_ENCRTYPED_ADDRESS_BYTES);
      let nft_id = 1;

      let signature = ALICE_TRANSFER_TO_BOB_SIGNATURE.to_string();

      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrtyped_address, alice_ephemeral_public_key),
        Ok(())
      );
      // Alice owns token 1.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(alice_encrtyped_address));

      // Bob does not owns any token.
      assert_eq!(erc721.balance_of(bob_encrtyped_address), 0);

      // The first Transfer event takes place.
      assert_eq!(1, ink_env::test::recorded_events().count());

      // Alice transfers token 1 to Bob.
      assert_eq!(
        erc721.transfer(
          bob_encrtyped_address,
          1,
          bob_ephemeral_public_key,
          signature
        ),
        Ok(())
      );
      // The second Transfer event takes place.
      assert_eq!(2, ink_env::test::recorded_events().count());

      // Bob owns token 1.
      assert_eq!(erc721.balance_of(bob_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(bob_encrtyped_address));
    }

    #[ink::test]
    fn invalid_transfer_should_fail() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let alice_ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let alice_encrtyped_address = AccountId::from(ALICE_ENCRTYPED_ADDRESS_BYTES);

      let bob_ephemeral_public_key = BOB_EPHEMERAL_PUBLIC_KEY.to_string();
      let bob_encrtyped_address = AccountId::from(BOB_ENCRTYPED_ADDRESS_BYTES);
      let nft_id = 1;

      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrtyped_address, alice_ephemeral_public_key),
        Ok(())
      );
      // Alice owns token 1.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(alice_encrtyped_address));

      // Bob cannot transfer not owned tokens.
      assert_eq!(
        erc721.transfer(
          bob_encrtyped_address,
          1,
          bob_ephemeral_public_key,
          ALICE_BURN_SIGNATURE.to_string()
        ),
        Err(Error::NotApproved)
      );
    }

    #[ink::test]
    fn burn_works() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let alice_ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let alice_encrtyped_address = AccountId::from(ALICE_ENCRTYPED_ADDRESS_BYTES);
      let nft_id = 1;

      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrtyped_address, alice_ephemeral_public_key),
        Ok(())
      );
      // Alice owns token 1.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(alice_encrtyped_address));

      // Destroy token Id 1.
      assert_eq!(erc721.burn(1, ALICE_BURN_SIGNATURE.to_string()), Ok(()));

      // Alice does not owns tokens.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 0);

      // Token Id 1 does not exists.
      assert_eq!(erc721.owner_of(1), None);
    }

    #[ink::test]
    fn burn_fails_token_not_found() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());

      // Try burning a non existent token.
      assert_eq!(
        erc721.burn(1, ALICE_BURN_SIGNATURE.to_string()),
        Err(Error::TokenNotFound)
      );
    }

    #[ink::test]
    fn burn_fails_not_owner() {
      // Create a new contract instance.
      let mut erc721 = Erc721::new(BASE_URI.to_string());
      let alice_ephemeral_public_key = ALICE_EPHEMERAL_PUBLIC_KEY.to_string();
      let alice_encrtyped_address = AccountId::from(ALICE_ENCRTYPED_ADDRESS_BYTES);
      let nft_id = 1;

      let signature = ALICE_TRANSFER_TO_BOB_SIGNATURE.to_string();

      // Create token Id 1 for Alice.
      assert_eq!(
        erc721.mint(alice_encrtyped_address, alice_ephemeral_public_key),
        Ok(())
      );

      // Alice owns token 1.
      assert_eq!(erc721.balance_of(alice_encrtyped_address), 1);

      // Owner owns NFT 1.
      assert_eq!(erc721.owner_of(nft_id), Some(alice_encrtyped_address));

      // Try burning this token with a different account.
      assert_eq!(erc721.burn(1, signature), Err(Error::NotOwner));
    }
  }
}
