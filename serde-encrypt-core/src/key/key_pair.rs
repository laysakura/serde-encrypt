//! X25519 key-pair (public-key and private-key).

pub mod private_key;
pub mod public_key;

use core::ops::DerefMut;

use self::{
    private_key::{ReceiverPrivateKey, SenderPrivateKey},
    public_key::{ReceiverPublicKey, SenderPublicKey},
};
use crate::random::RngSingleton;
use crypto_box::{PublicKey, SecretKey};

/// X25519 Key-pair generated by sender.
pub trait SenderKeyPairCore {
    /// RNG singleton
    type R: RngSingleton;

    /// Constructor
    fn new(sender_private_key: SenderPrivateKey, sender_public_key: SenderPublicKey) -> Self
    where
        Self: Sized;

    /// Generates a key-pair for message sender.
    fn generate() -> Self
    where
        Self: Sized,
    {
        let (private_key, public_key) = gen_key_pair::<Self::R>();
        let sender_private_key = SenderPrivateKey::from(private_key);
        let sender_public_key = SenderPublicKey::from(public_key);
        Self::new(sender_private_key, sender_public_key)
    }

    /// Ref to private key.
    fn private_key(&self) -> &SenderPrivateKey;

    /// Ref to public key.
    fn public_key(&self) -> &SenderPublicKey;
}

/// X25519 Key-pair generated by receiver.
pub trait ReceiverKeyPairCore {
    /// RNG singleton
    type R: RngSingleton;

    /// Constructor
    fn new(
        receiver_private_key: ReceiverPrivateKey,
        receiver_public_key: ReceiverPublicKey,
    ) -> Self
    where
        Self: Sized;

    /// Generates a key-pair for message receiver.
    fn generate() -> Self
    where
        Self: Sized,
    {
        let (private_key, public_key) = gen_key_pair::<Self::R>();
        let receiver_private_key = ReceiverPrivateKey::from(private_key);
        let receiver_public_key = ReceiverPublicKey::from(public_key);
        Self::new(receiver_private_key, receiver_public_key)
    }

    /// Ref to private key.
    fn private_key(&self) -> &ReceiverPrivateKey;

    /// Ref to public key.
    fn public_key(&self) -> &ReceiverPublicKey;
}

fn gen_key_pair<R>() -> (SecretKey, PublicKey)
where
    R: RngSingleton,
{
    let mut rng = R::instance();

    let secret_key = SecretKey::generate(rng.deref_mut());
    let public_key = secret_key.public_key();

    (secret_key, public_key)
}
