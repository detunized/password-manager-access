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
            var key = Crypto.DeriveKey("username", "password", 100);
            Assert.That(key, Is.EqualTo("antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=".Decode64()));
        }

        [Test]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            var key = Crypto.DeriveKey(" UsErNaMe ", "password", 100);
            Assert.That(key, Is.EqualTo("antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=".Decode64()));
        }
    }
}
