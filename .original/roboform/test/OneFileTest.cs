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

        [Test]
        public void Decrypt_throws_on_no_content()
        {
            Assert.That(Decrypt("too short".ToBytes()),
                        ExceptionsTest.ThrowsParseErrorWithMessage("too short"));
        }

        [Test]
        public void Decrypt_throws_on_invalid_signature()
        {
            Assert.That(DecryptPad("invalid!"),
                        ExceptionsTest.ThrowsParseErrorWithMessage("signature"));
        }

        [Test]
        public void Decrypt_throws_on_unsupported_sha1_kdf()
        {
            Assert.That(DecryptPad("gsencst1\x00" + "\x01"),
                        ExceptionsTest.ThrowsUnsupportedFeatureWithMessage("SHA-1"));
        }

        [Test]
        public void Decrypt_throws_on_unsupported_invalid_kdf()
        {
            Assert.That(DecryptPad("gsencst1\x00" + "\x05"),
                        ExceptionsTest.ThrowsParseErrorWithMessage("KDF/encryption type"));
        }

        [Test]
        public void Decrypt_throws_on_invalid_iteration_count()
        {
            var iterations = new[] {new byte[] {0, 0, 0, 0}, new byte[] {0, 0x08, 0, 1}};
            foreach (var i in iterations)
            {
                Assert.That(DecryptPad("gsencst1\x00\x02".ToBytes().Concat(i).ToArray()),
                            ExceptionsTest.ThrowsParseErrorWithMessage("iteration count"));
            }
        }

        [Test]
        public void Decrypt_throws_on_too_short_salt()
        {
            Assert.That(DecryptPad("gsencst1\x00\x02\x00\x10\x00\x00\x10" + "salt..."),
                        ExceptionsTest.ThrowsParseErrorWithMessage("too short"));
        }

        [Test]
        public void Decrypt_throws_on_too_short_extra()
        {
            Assert.That(DecryptPad("gsencst1\x10\x02\x00\x10\x00\x00\x10saltsaltsaltsalt" + "extra..."),
                        ExceptionsTest.ThrowsParseErrorWithMessage("too short"));
        }

        [Test]
        public void Decompress_returns_decompressed_data()
        {
            // Generated with bash
            // $ echo -n decompressed | gzip -c - | base64
            Assert.That(
                OneFile.Decompress("H4sIANRVH1oAA0tJTc7PLShKLS5OTQEACojeBQwAAAA=".Decode64()),
                Is.EqualTo("decompressed".ToBytes()));
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
            return Parse(Pad(content, 30));
        }

        private static TestDelegate Parse(byte[] content)
        {
            return () => OneFile.Parse(content, "password");
        }

        private static TestDelegate DecryptPad(string content)
        {
            return DecryptPad(content.ToBytes());
        }

        private static TestDelegate DecryptPad(byte[] content)
        {
            return Decrypt(Pad(content, 15));
        }

        private static TestDelegate Decrypt(byte[] content)
        {
            return () => OneFile.Decrypt(content, "password");
        }

        private static byte[] Pad(byte[] content, int minLength)
        {
            if (content.Length >= minLength)
                return content;

            return content.Concat(new byte[minLength - content.Length]).ToArray();
        }
    }
}
