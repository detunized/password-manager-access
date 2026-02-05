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
        return decrypted.ToUtf8().Decode64();
    }
}
