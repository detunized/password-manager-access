using System;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        [Test]
        public void Reverse()
        {
            Assert.AreEqual(0u, 0u.Reverse());
            Assert.AreEqual(0xffu, 0xff000000u.Reverse());
            Assert.AreEqual(0xff000000u, 0xffu.Reverse());
            Assert.AreEqual(0xff00ff00u, 0xff00ffu.Reverse());
            Assert.AreEqual(0x78563412u, 0x12345678u.Reverse());
            Assert.AreEqual(0xdeadbeefu, 0xefbeaddeu.Reverse());
        }

        [Test]
        public void FromBigEndian()
        {
            Assert.AreEqual(0u, BitConverter.ToUInt32(new byte[] {0x00, 0x00, 0x00, 0x00}, 0).FromBigEndian());
            Assert.AreEqual(0x12345678u, BitConverter.ToUInt32(new byte[] {0x12, 0x34, 0x56, 0x78}, 0).FromBigEndian());
            Assert.AreEqual(0xdeadbeefu, BitConverter.ToUInt32(new byte[] {0xde, 0xad, 0xbe, 0xef}, 0).FromBigEndian());
        }

        [Test]
        public void ToUtf8()
        {
            Assert.AreEqual("", new byte[] {}.ToUtf8());
            Assert.AreEqual(_helloUtf8, _helloUtf8Bytes.ToUtf8());
        }

        [Test]
        public void ToHex()
        {
            Assert.AreEqual("", new byte[] {}.ToHex());
            Assert.AreEqual(_helloHex, _helloHexBytes.ToHex());
        }

        [Test]
        public void ToBytes()
        {
            Assert.AreEqual(new byte[] {}, "".ToBytes());
            Assert.AreEqual(_helloUtf8Bytes, _helloUtf8.ToBytes());
        }

        [Test]
        public void Decode64()
        {
            Assert.AreEqual(new byte[] {}, "".Decode64());
            Assert.AreEqual(new byte[] {0x61}, "YQ==".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62}, "YWI=".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        private readonly string _helloUtf8 = "Hello, UTF-8!";
        private readonly byte[] _helloUtf8Bytes = new byte[] {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x21};
        private readonly string _helloHex = "48656c6c6f2c2048455821"; // "Hello, HEX!"
        private readonly byte[] _helloHexBytes = new byte[] {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x48, 0x45, 0x58, 0x21};
    }
}
