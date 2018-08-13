// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void DeriveKek_returns_key()
        {
            var expected = new KeyMac("a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e13IOFMfmCJORzuf" +
                                      "hnDVeB4cDrxnTsPFYMTvpHboE8MPGg==");
            var kek = Crypto.DeriveKek("password".ToBytes(), "pzJ5y/CiCeU8Sbo8+k4/zg==".Decode64(), 40000);

            Assert.That(kek.Key, Is.EqualTo(expected.Key));
            Assert.That(kek.MacKey, Is.EqualTo(expected.MacKey));
        }
    }
}
