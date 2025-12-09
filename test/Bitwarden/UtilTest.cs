// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class UtilTest
    {
        [Fact]
        public void DeriveKey_returns_derived_key_pbkdf2()
        {
            // Arrange/Act
            var key = Util.DeriveKey(Username, Password, Pbkdf2KdfInfo);

            // Assert
            key.ShouldBe(DerivedKeyPbkdf2.Decode64());
        }

        [Fact]
        public void DeriveKey_returns_derived_key_argon2id()
        {
            // Arrange/Act
            var key = Util.DeriveKey(Username, Password, Argon2idKdfInfo);

            // Assert
            key.ShouldBe(DerivedKeyArgon2id.Decode64());
        }

        [Fact]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            // Arrange/Act
            var key = Util.DeriveKey(" UsErNaMe ", Password, Pbkdf2KdfInfo);

            // Assert
            key.ShouldBe(DerivedKeyPbkdf2.Decode64());
        }

        [Fact]
        public void DeriveKey_throws_on_unsupported_kdf()
        {
            // Arrange/Act
            var act = () => Util.DeriveKey(Username, Password, new Model.KdfInfo { Kdf = (Model.KdfMethod)13, Iterations = -13 });

            // Assert
            var ex = Should.Throw<UnsupportedFeatureException>(act);
            ex.Message.ShouldContain("KDF method");
        }

        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            // Arrange/Act
            var hash = Util.HashPassword(Password, DerivedKeyPbkdf2.Decode64());

            // Assert
            hash.ShouldBe(PasswordHash.Decode64());
        }

        [Fact]
        public void HkdfExpand_returns_expected_result()
        {
            // Arrange/Act
            var result = Util.HkdfExpand("prk".ToBytes(), "info".ToBytes());

            // Assert
            result.ShouldBe("t+eNA48Gl56FVhjNqTxs9cktUhG28eg3i/Rbf0QtPSU=".Decode64());
        }

        [Fact]
        public void ExpandKey_expands_key_to_64_bytes()
        {
            // Arrange
            var expected = "GKPlyJlfe4rO+RNeBj6P4Jm1Ds4QFB23rN2WvwVcb5Iw0U+9uVf7jwQ04Yq75uCrOSsL7HonzBzNdYi1hO/mlQ==";

            // Act
            var result = Util.ExpandKey("key".ToBytes());

            // Assert
            result.ShouldBe(expected.Decode64());
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string DerivedKeyPbkdf2 = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string DerivedKeyArgon2id = "qwJqLHT2PdOduAiV1cfA9bXk3iDCa0sVSJG1mWuKVEk=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";
        private static readonly Model.KdfInfo Pbkdf2KdfInfo = new() { Kdf = Model.KdfMethod.Pbkdf2Sha256, Iterations = 100 };
        private static readonly Model.KdfInfo Argon2idKdfInfo =
            new()
            {
                Kdf = Model.KdfMethod.Argon2id,
                Iterations = 3,
                Memory = 64,
                Parallelism = 4,
            };
    }
}
