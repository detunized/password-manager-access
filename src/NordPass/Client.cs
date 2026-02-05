// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.NordPass;

internal static class Client
{
    // Decrypts the identity private key using the master key.
    // Returns the raw Ed25519 keypair (64 bytes: 32-byte seed + 32-byte public key).
    internal static byte[] DecryptIdentityKey(byte[] masterKey, byte[] encryptedPrivateKey)
    {
        var decrypted = Crypto.DecryptXChaCha20Poly1305(encryptedPrivateKey, masterKey);
        return decrypted.Decode64();
    }

    // Decrypts the item private key using the identity X25519 keypair (sealed box).
    // Returns the raw Ed25519 keypair (64 bytes: 32-byte seed + 32-byte public key).
    internal static byte[] DecryptItemKey(byte[] identityX25519PublicKey, byte[] identityX25519PrivateKey, byte[] encryptedItemPrivateKey)
    {
        var decrypted = Crypto.DecryptSealedBox(encryptedItemPrivateKey, identityX25519PublicKey, identityX25519PrivateKey);
        return decrypted.Decode64();
    }

    // Decrypts the value key using the item X25519 keypair (sealed box).
    // Returns the 32-byte symmetric key used to decrypt the item value.
    internal static byte[] DecryptValueKey(byte[] itemX25519PublicKey, byte[] itemX25519PrivateKey, byte[] encryptedValueKey)
    {
        var decrypted = Crypto.DecryptSealedBox(encryptedValueKey, itemX25519PublicKey, itemX25519PrivateKey);
        return decrypted.Decode64();
    }
}
