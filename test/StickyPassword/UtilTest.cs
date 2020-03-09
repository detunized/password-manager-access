// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class UtilTest
    {
        [Fact]
        public void DecryptToken_returns_token()
        {
            // The actual bytes dumped from the running app
            var expected = "e450ec3dee464c7ea158cb707f86c52d".ToBytes();
            var encryptedToken = new byte[]
            {
                0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
                0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
                0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
                0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40
            };

            Assert.Equal(expected, Util.DecryptToken(Username, Password, encryptedToken));
        }

        [Fact]
        public void DeriveTokenKey_returns_key()
        {
            // The actual bytes dumped from the running app
            var expected = new byte[]
            {
                0xaa, 0xae, 0xbb, 0xde, 0x84, 0x75, 0x3e, 0x78,
                0xd2, 0x5a, 0xf5, 0x4a, 0xf3, 0x35, 0x7d, 0xae,
                0xee, 0x26, 0x48, 0x27, 0x6f, 0x0b, 0x79, 0x78,
                0xaa, 0x8f, 0x5c, 0x2f, 0x81, 0x0c, 0xb4, 0xf1
            };

            Assert.Equal(expected, Util.DeriveTokenKey(Username, Password));
        }

        [Fact]
        public void DeriveDbKey_returns_key()
        {
            Assert.Equal(DbKey, Util.DeriveDbKey(Password, DbKeySalt));
        }

        [Fact]
        public void Decrypt_returns_plaintext()
        {
            Assert.Equal(AesPlaintext, Util.Decrypt(AesCiphertext, AesKey));
        }

        [Fact]
        public void Encrypt_returns_ciphertext()
        {
            Assert.Equal(AesCiphertext, Util.Encrypt(AesPlaintext, AesKey));
        }

        //
        // Data
        //

        private const string Username = "LastPass.Ruby@gmaiL.cOm";
        private const string Password = "Password123";

        // The actual bytes from the user database
        private static readonly byte[] DbKeySalt =
        {
            0x63, 0x51, 0xee, 0x97, 0x8c, 0x6e, 0xe0, 0xd8,
            0x1e, 0x66, 0xdf, 0x61, 0x90, 0x3a, 0x5a, 0x88
        };

        // The actual bytes dumped from the running app
        private static readonly byte[] DbKey =
        {
            0x69, 0xd6, 0xb0, 0xd2, 0x50, 0x8e, 0x4b, 0x83,
            0x4a, 0xb9, 0xe3, 0x14, 0x3c, 0x40, 0x81, 0x44,
            0x75, 0x44, 0x47, 0x95, 0x43, 0x72, 0x01, 0xf8,
            0x8f, 0xb6, 0x97, 0xd8, 0xdd, 0x55, 0xa1, 0x41
        };

        // Generated with Ruby/openssl
        private static readonly byte[] AesKey = "this is a very secure password!!".ToBytes();
        private static readonly byte[] AesPlaintext = "decrypted data!".ToBytes();
        private static readonly byte[] AesCiphertext = "BwhwrWXJmDUFR30GJT5fjw==".Decode64();
    }
}
