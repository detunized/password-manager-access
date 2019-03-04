// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Keeper
{
    using System.IO;
    using System.Linq;
    using PasswordManagerAccess.Common;
    using C = Common.Crypto;

    internal static class Crypto
    {
        public static byte[] HashPassword(string password, byte[] salt, int iterations)
        {
            return C.Sha256(C.Pbkdf2Sha256(password, salt, iterations, 32));
        }

        internal static byte[] DecryptVaultKey(byte[] encodedKey, string password)
        {
            using (var r = new BinaryReader(new MemoryStream(encodedKey, false)))
            {
                var version = r.ReadByte();
                var iterations = (r.ReadByte() << 16) | (r.ReadByte() << 8) | r.ReadByte();
                var salt = r.ReadBytes(16);
                var iv = r.ReadBytes(16);
                var ciphertext = r.ReadBytes(64);

                var key = C.Pbkdf2Sha256(password, salt, iterations, 32);
                var plaintext = C.DecryptAes256CbcNoPadding(ciphertext, iv, key);

                // Verification: must be the same value twice
                var vaultKey = plaintext.Take(32);
                var verification = plaintext.Skip(32).Take(32);

                if (!vaultKey.SequenceEqual(verification))
                    throw new InternalErrorException("Vault key decryption failed");

                return vaultKey.ToArray();
            }
        }

        // Container: 16 byte iv + padded ciphertext
        internal static byte[] DecryptContainer(byte[] container, byte[] key)
        {
            var paddedPlaintext = C.DecryptAes256CbcNoPadding(container.Skip(16).ToArray(),
                                                              container.Take(16).ToArray(),
                                                              key);
            return UnpadPlaintext(paddedPlaintext);
        }

        private static byte[] UnpadPlaintext(byte[] paddedPlaintext)
        {
            var paddingLength = paddedPlaintext.Last();
            return paddedPlaintext.Take(paddedPlaintext.Length - paddingLength).ToArray();
        }
    }
}
