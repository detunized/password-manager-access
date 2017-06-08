// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void RandomBytes_returns_array_of_requested_size()
        {
            foreach (var size in new[] { 0, 1, 2, 3, 4, 15, 255, 1024, 1337 })
                Assert.That(Crypto.RandomBytes(size).Length, Is.EqualTo(size));
        }

        [Test]
        public void Sha256_returns_hashed_message()
        {
            // Just a simple smoke test. Don't need to test SHA extensively.
            // Only to see we didn't mess something simple up.
            Assert.That(Crypto.Sha256("message"),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }
    }
}
