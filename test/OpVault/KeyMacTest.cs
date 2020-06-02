// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordManagerAccess.Test.OpVault
{
    [TestFixture]
    public class KeyMacTest
    {
        [Test]
        public void KeyMac_created_from_bytes()
        {
            var key = new KeyMac(Buffer.Decode64());

            Assert.That(key.Key, Is.EqualTo(Key.Decode64()));
            Assert.That(key.MacKey, Is.EqualTo(MacKey.Decode64()));
        }

        [Test]
        public void KeyMac_created_from_base64()
        {
            var key = new KeyMac(Buffer);

            Assert.That(key.Key, Is.EqualTo(Key.Decode64()));
            Assert.That(key.MacKey, Is.EqualTo(MacKey.Decode64()));
        }

        //
        // Data
        //

        private const string Buffer = "a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e13IOFMfmCJORzuf" +
                                      "hnDVeB4cDrxnTsPFYMTvpHboE8MPGg==";
        private const string Key = "a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e10=";
        private const string MacKey = "yDhTH5giTkc7n4Zw1XgeHA68Z07DxWDE76R26BPDDxo=";
    }
}
