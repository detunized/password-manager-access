// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        [Test]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.AreEqual(new byte[] { }, "".ToBytes());
            Assert.AreEqual(
                new byte[] {
                    65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97, 114,
                    101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115 },
                "All your base are belong to us".ToBytes());
        }

        [Test]
        public void String_Decode64_decodes_base64()
        {
            Assert.AreEqual(new byte[] { }, "".Decode64());
            Assert.AreEqual(new byte[] { 0x61 }, "YQ==".Decode64());
            Assert.AreEqual(new byte[] { 0x61, 0x62 }, "YWI=".Decode64());
            Assert.AreEqual(new byte[] { 0x61, 0x62, 0x63 }, "YWJj".Decode64());
            Assert.AreEqual(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA==".Decode64());
        }
    }
}
