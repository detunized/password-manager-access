// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string DerivedKey = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";

    }
}
