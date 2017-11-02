// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using RoboForm;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class ExtensionsTest
    {
        //
        // string
        //

        [Test]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.That("".ToBytes(), Is.EqualTo(new byte[] { }));
            Assert.That(TestString.ToBytes(), Is.EqualTo(TestBytes));
        }

        [Test]
        public void String_EscapeUri_escapes_special_characters()
        {
            var testCases = new Dictionary<string, string>
            {
                // TODO: Add more test cases to make sure it matches JS.
                {"", ""},
                {";,/?:@&=+$#", ";,/?:@&=+$#"},
                {"-_.!~*'()", "-_.!~*'()"},
                {"ABC abc 123", "ABC%20abc%20123"},
            };

            foreach (var i in testCases)
                Assert.That(i.Key.EncodeUri(), Is.EqualTo(i.Value));
        }

        //
        // byte[]
        //

        [Test]
        public void ByteArray_ToBase64_returns_base64()
        {
            Assert.That(new byte[] { }.ToBase64(), Is.EqualTo(""));
            Assert.That(new byte[] { 0x61 }.ToBase64(), Is.EqualTo("YQ=="));
            Assert.That(new byte[] { 0x61, 0x62 }.ToBase64(), Is.EqualTo("YWI="));
            Assert.That(new byte[] { 0x61, 0x62, 0x63 }.ToBase64(), Is.EqualTo("YWJj"));
            Assert.That(new byte[] { 0x61, 0x62, 0x63, 0x64 }.ToBase64(), Is.EqualTo("YWJjZA=="));
        }

        //
        // Data
        //

        private const string TestString = "All your base are belong to us";
        private static readonly byte[] TestBytes =
        {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

    }
}
