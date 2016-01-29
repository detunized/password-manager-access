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
            Assert.That(
                "".ToBytes(),
                Is.EqualTo(new byte[] {}));

            Assert.That(
                "All your base are belong to us".ToBytes(),
                Is.EqualTo(new byte[] {
                    65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97, 114,
                    101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115 }
                ));
        }

        [Test]
        public void String_Decode64_decodes_base64()
        {
            Assert.That("".Decode64(), Is.EqualTo(new byte[] {}));
            Assert.That("YQ==".Decode64(), Is.EqualTo(new byte[] { 0x61 }));
            Assert.That("YWI=".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62 }));
            Assert.That("YWJj".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63 }));
            Assert.That("YWJjZA==".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63, 0x64 }));
        }
    }
}
