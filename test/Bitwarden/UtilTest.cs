// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class UtilTest
    {
        [Fact]
        public void DeriveKey_returns_derived_key()
        {
            var key = Util.DeriveKey(Username, Password, 100);
            Assert.Equal(DerivedKey.Decode64(), key);
        }

        [Fact]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            var key = Util.DeriveKey(" UsErNaMe ", Password, 100);
            Assert.Equal(DerivedKey.Decode64(), key);
        }

        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Util.HashPassword(Password, DerivedKey.Decode64());
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
        private const string DerivedKey = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";
    }
}
