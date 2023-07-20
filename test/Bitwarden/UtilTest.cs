// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Xunit;
using R = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class UtilTest
    {
        [Fact]
        public void DeriveKey_returns_derived_key_pbkdf2()
        {
            var key = Util.DeriveKey(Username, Password, Pbkdf2KdfInfo);
            Assert.Equal(DerivedKeyPbkdf2.Decode64(), key);
        }

        [Fact]
        public void DeriveKey_returns_derived_key_argon2id()
        {
            var key = Util.DeriveKey(Username, Password, Argon2idKdfInfo);
            Assert.Equal(DerivedKeyArgon2id.Decode64(), key);
        }

        [Fact]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            var key = Util.DeriveKey(" UsErNaMe ", Password, Pbkdf2KdfInfo);
            Assert.Equal(DerivedKeyPbkdf2.Decode64(), key);
        }

        [Fact]
        public void DeriveKey_throws_on_unsupported_kdf()
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Util.DeriveKey(Username, Password, new R.KdfInfo { Kdf = (R.KdfMethod)13 }),
                "KDF method");
        }

        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Util.HashPassword(Password, DerivedKeyPbkdf2.Decode64());
            Assert.Equal(PasswordHash.Decode64(), hash);
        }

        [Fact]
        public void HkdfExpand_returns_expected_result()
        {
            Assert.Equal("t+eNA48Gl56FVhjNqTxs9cktUhG28eg3i/Rbf0QtPSU=".Decode64(),
                         Util.HkdfExpand("prk".ToBytes(), "info".ToBytes()));
        }

        [Fact]
        public void ExpandKey_expands_key_to_64_bytes()
        {
            var expected = "GKPlyJlfe4rO+RNeBj6P4Jm1Ds4QFB23rN2WvwVcb5Iw0U+9uVf7jwQ04Yq75uCrOSsL7HonzBzNdYi1hO/mlQ==";
            Assert.Equal(expected.Decode64(), Util.ExpandKey("key".ToBytes()));
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string DerivedKeyPbkdf2 = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string DerivedKeyArgon2id = "qwJqLHT2PdOduAiV1cfA9bXk3iDCa0sVSJG1mWuKVEk=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";
        private static readonly R.KdfInfo Pbkdf2KdfInfo = new R.KdfInfo
        {
            Kdf = R.KdfMethod.Pbkdf2Sha256,
            Iterations = 100,
        };
        private static readonly R.KdfInfo Argon2idKdfInfo = new R.KdfInfo
        {
            Kdf = R.KdfMethod.Argon2id,
            Iterations = 3,
            Memory = 64,
            Parallelism = 4,
        };
    }
}
