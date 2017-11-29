// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    class OneFileTest
    {
        [Test]
        public void Parse_returns_parsed_object()
        {
            Assert.That(() => OneFile.Parse(TestData.Blob, TestData.Password), Throws.Nothing);
        }

        [Test]
        public void Parse_throws_on_no_content()
        {
            Assert.That(Parse("too short".ToBytes()),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("too short"));
        }

        [Test]
        public void Parse_throws_on_invalid_signature()
        {
            Assert.That(ParsePad("invalid!"),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("signature"));
        }

        [Test]
        public void Parse_throws_unencrypted_content()
        {
            Assert.That(ParsePad("onefile1"+ "\x05"),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("Unencrypted"));
        }

        [Test]
        public void Parse_throws_on_invalid_checksum_type()
        {
            Assert.That(ParsePad("onefile1\x07" + "\x13"),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("checksum"));
        }

        [Test]
        public void Parse_throws_on_invalid_content_length()
        {
            var lengths = new[] {new byte[] {0, 0, 0, 0x80}, new byte[] {0xFF, 0xFF, 0xFF, 0xFF}};
            foreach (var i in lengths)
            {
                Assert.That(ParsePad("onefile1\x07\x01".ToBytes().Concat(i).ToArray()),
                            Throws.TypeOf<InvalidOperationException>()
                                .And.Message.Contains("negative"));
            }
        }

        [Test]
        public void Parse_throws_on_invalid_checksum()
        {
            Assert.That(ParsePad("onefile1\x07\x01\x01\x00\x00\x00" + "invalid checksum" + "!"),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("Checksum"));
        }

        [Test]
        public void Parse_throws_on_too_short_content()
        {
            Assert.That(ParsePad("onefile1\x07\x01\x02\x00\x00\x00" + "invalid checksum" + "!"),
                        Throws.TypeOf<InvalidOperationException>().And.Message.Contains("too short"));
        }

        //
        // Helpers
        //

        private static TestDelegate ParsePad(string content)
        {
            return ParsePad(content.ToBytes());
        }

        private static TestDelegate ParsePad(byte[] content)
        {
            const int minLength = 30;

            // Pad to prevent "too short" error
            if (content.Length < minLength)
                content = content.Concat(new byte[minLength - content.Length]).ToArray();

            return Parse(content);
        }

        private static TestDelegate Parse(byte[] content)
        {
            return () => OneFile.Parse(content, "password");
        }
    }
}
