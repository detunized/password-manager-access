// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Konscious.Security.Cryptography;
using NaCl;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.NordPass;

// Some libsodium functions (sealed box, Ed25519-to-X25519 conversion) are reimplemented here
// using NaCl.Net and BouncyCastle to avoid pulling in a native libsodium binary dependency.
internal static class Crypto
{
    // Argon2id parameters from the NordPass Android app
    public const int Argon2MemorySize = 65536; // 64 MB in KB
    public const int Argon2Iterations = 4;
    public const int Argon2Parallelism = 1;
    public const int Argon2OutputLength = 32;

    public static byte[] DeriveKey(string password, byte[] salt)
    {
        return new Argon2id(password.ToBytes())
        {
            Salt = salt,
            Iterations = Argon2Iterations,
            MemorySize = Argon2MemorySize,
            DegreeOfParallelism = Argon2Parallelism,
        }.GetBytes(Argon2OutputLength);
    }

    // NordPass format: nonce (24 bytes) || ciphertext || tag (16 bytes)
    public static byte[] DecryptXChaCha20Poly1305(byte[] ciphertextWithNonce, byte[] key)
    {
        if (ciphertextWithNonce.Length < 24 + 16)
            throw new InternalErrorException("Ciphertext is too short");

        var nonce = ciphertextWithNonce[..24];
        var ciphertext = ciphertextWithNonce[24..];

        return Common.Crypto.DecryptXChaCha20Poly1305(ciphertext, nonce, key);
    }

    // crypto_box_seal_open: ephemeral_pk (32) || crypto_box ciphertext
    // Nonce is derived as Blake2b(ephemeral_pk || recipient_pk, 24)
    public static byte[] DecryptSealedBox(byte[] ciphertext, byte[] publicKey, byte[] privateKey)
    {
        if (ciphertext.Length < 32 + XSalsa20Poly1305.TagLength)
            throw new InternalErrorException("Sealed box ciphertext is too short");

        var ephemeralPk = ciphertext[..32];
        var boxCiphertext = ciphertext[32..];

        var nonce = Blake2b(24, ephemeralPk, publicKey);

        var plaintext = new byte[boxCiphertext.Length - XSalsa20Poly1305.TagLength];
        if (!new Curve25519XSalsa20Poly1305(privateKey, ephemeralPk).TryDecrypt(plaintext, boxCiphertext, nonce))
            throw new InternalErrorException("Failed to decrypt sealed box");

        return plaintext;
    }

    // crypto_sign_ed25519_sk_to_curve25519: SHA-512(seed)[0:32] clamped
    public static byte[] Ed25519ToX25519Private(byte[] ed25519SecretKey)
    {
        var hash = Common.Crypto.Sha512(ed25519SecretKey[..32]);
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;
        return hash[..32];
    }

    // crypto_sign_ed25519_pk_to_curve25519: convert twisted Edwards point to Montgomery
    // u = (1 + y) / (1 - y) mod p, where p = 2^255 - 19
    public static byte[] Ed25519ToX25519Public(byte[] ed25519PublicKey)
    {
        // Decode y-coordinate from the Ed25519 public key (little-endian, top bit is sign of x)
        var yBytes = (byte[])ed25519PublicKey.Clone();
        yBytes[31] &= 0x7F;
        Array.Reverse(yBytes); // to big-endian for BigInteger
        var y = new BigInteger(1, yBytes);

        // u = (1 + y) * (1 - y)^(-1) mod p
        var numerator = BigInteger.One.Add(y).Mod(P);
        var denominator = BigInteger.One.Subtract(y).Mod(P);
        var u = numerator.Multiply(denominator.ModInverse(P)).Mod(P);

        // Encode u as 32 bytes little-endian
        var uBytes = u.ToByteArrayUnsigned();
        Array.Reverse(uBytes);
        var result = new byte[32];
        Buffer.BlockCopy(uBytes, 0, result, 0, Math.Min(uBytes.Length, 32));
        return result;
    }

    //
    // Internal
    //

    // p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.One.ShiftLeft(255).Subtract(BigInteger.ValueOf(19));

    internal static byte[] Blake2b(int outputLength, byte[] a, byte[] b)
    {
        var digest = new Blake2bDigest(null, outputLength, null, null);
        digest.BlockUpdate(a, 0, a.Length);
        digest.BlockUpdate(b, 0, b.Length);
        var output = new byte[outputLength];
        digest.DoFinal(output, 0);
        return output;
    }
}
