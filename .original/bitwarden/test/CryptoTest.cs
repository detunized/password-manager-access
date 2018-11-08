// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void DeriveKey_returns_derived_key()
        {
            var key = Crypto.DeriveKey(Username, Password, 100);
            Assert.That(key, Is.EqualTo(DerivedKey.Decode64()));
        }

        [Test]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            var key = Crypto.DeriveKey(" UsErNaMe ", Password, 100);
            Assert.That(key, Is.EqualTo(DerivedKey.Decode64()));
        }

        [Test]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Crypto.HashPassword(Password, DerivedKey.Decode64());
            Assert.That(hash, Is.EqualTo(PasswordHash.Decode64()));
        }

        [Test]
        public void Hmac256_bytes_returns_hashed_message()
        {
            Assert.That(Crypto.Hmac("salt".ToBytes(), "message".ToBytes()),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        [Test]
        public void HkdfExpand_returns_expected_result()
        {
            Assert.That(Crypto.HkdfExpand("prk".ToBytes(), "info".ToBytes()),
                        Is.EqualTo("t+eNA48Gl56FVhjNqTxs9cktUhG28eg3i/Rbf0QtPSU=".Decode64()));
        }

        [Test]
        public void ExpandKey_expands_key_to_64_bytes()
        {
            var expected = "GKPlyJlfe4rO+RNeBj6P4Jm1Ds4QFB23rN2WvwVcb5Iw0U+9uVf7jwQ04Yq75uCrOSsL7HonzBzNdYi1hO/mlQ==";
            Assert.That(Crypto.ExpandKey("key".ToBytes()), Is.EqualTo(expected.Decode64()));
        }

        [Test]
        public void DecryptAes256_decrypts_ciphertext()
        {
            Assert.That(
                Crypto.DecryptAes256("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                     "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                     "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64()),
                Is.EqualTo("All your base are belong to us".ToBytes()));
        }

        [Test]
        public void DecryptAes256_throws_on_incorrect_encryption_key()
        {
            Assert.That(() => Crypto.DecryptAes256("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                                   "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                                   "Incorrect key must be 32 bytes!!".ToBytes()),
                        Throws
                            .InstanceOf<ClientException>()
                            .And.Property("Reason").EqualTo(ClientException.FailureReason.CryptoError)
                            .And.Message.EqualTo("Decryption failed")
                            .And.InnerException.InstanceOf<CryptographicException>());
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string DerivedKey = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";
    }
}
