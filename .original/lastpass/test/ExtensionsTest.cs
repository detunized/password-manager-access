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
    }
}
