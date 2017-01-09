// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace StickyPassword.Test
{
    [TestFixture]
    class CryptoTest
    {
        public const string Username = "LastPass.Ruby@gmaiL.cOm";
        public const string Password = "Password123";
        public static readonly byte[] EncryptedToken = new byte[]
        {
            0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
            0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
            0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
            0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40
        };
        public static readonly byte[] Token = "e450ec3dee464c7ea158cb707f86c52d".ToBytes();

        [Test]
        public void DecryptToken_returns_token()
        {
            Assert.That(Crypto.DecryptToken(Username, Password, Token), Is.EqualTo(Token));
        }

        [Test]
        public void DeriveTokenKey_returns_key()
        {
            var expected = new byte[]
            {
                0xaa, 0xae, 0xbb, 0xde, 0x84, 0x75, 0x3e, 0x78,
                0xd2, 0x5a, 0xf5, 0x4a, 0xf3, 0x35, 0x7d, 0xae,
                0xee, 0x26, 0x48, 0x27, 0x6f, 0x0b, 0x79, 0x78,
                0xaa, 0x8f, 0x5c, 0x2f, 0x81, 0x0c, 0xb4, 0xf1
            };

            Assert.That(Crypto.DeriveTokenKey(Username, Password), Is.EqualTo(expected));
        }

        [Test]
        public void Md5_computes_md5()
        {
            // From http://www.nsrl.nist.gov/testdata/
            var expected = new byte[]
            {
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
            };

            Assert.That(Crypto.Md5("abc"), Is.EqualTo(expected));
        }
    }
}
