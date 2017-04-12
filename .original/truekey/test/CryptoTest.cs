// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class CryptoTest
    {
        [Test]
        public void HashPassword_returns_hash_string()
        {
            Assert.That(
                Crypto.HashPassword("username", "password"),
                Is.EqualTo("tk-v1-463d82f8e2378ed234ff98a84118636168b76a69cdac5fcb2b9594a0b18ad2ea"));
        }

        [Test]
        public void Sha256_returns_hashed_message()
        {
            Assert.That(Crypto.Sha256("message"),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }
    }
}
