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
            var encryptedToken = "2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=".Decode64();

            Assert.Equal(expected, Util.DecryptToken(Username, Password, encryptedToken));
        }

        [Fact]
        public void DeriveTokenKey_returns_key()
        {
            // The actual bytes dumped from the running app
            var expected = "qq673oR1PnjSWvVK8zV9ru4mSCdvC3l4qo9cL4EMtPE=".Decode64();

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
        private static readonly byte[] DbKeySalt = "Y1Hul4xu4NgeZt9hkDpaiA==".Decode64();

        // The actual bytes dumped from the running app
        private static readonly byte[] DbKey = "adaw0lCOS4NKueMUPECBRHVER5VDcgH4j7aX2N1VoUE=".Decode64();

        // Generated with Ruby/openssl
        private static readonly byte[] AesKey = "this is a very secure password!!".ToBytes();
        private static readonly byte[] AesPlaintext = "decrypted data!".ToBytes();
        private static readonly byte[] AesCiphertext = "BwhwrWXJmDUFR30GJT5fjw==".Decode64();
    }
}
