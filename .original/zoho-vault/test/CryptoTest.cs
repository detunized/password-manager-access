// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace ZohoVault.Test
{
    [TestFixture]
    class CryptoTest
    {
        public readonly byte[] Key = "d7643007973dba7243d724f66fd806bf".ToBytes();

        [Test]
        public void ComputeAesCtrKey_returns_key()
        {
            Assert.That(
                Crypto.ComputeAesCtrKey(Key).ToHex(),
                Is.EqualTo("1fad494b86d62e89f945e8cfb9925e341fad494b86d62e89f945e8cfb9925e34"));
        }
    }
}
