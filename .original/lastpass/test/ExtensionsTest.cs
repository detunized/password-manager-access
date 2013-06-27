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
    }
}
