// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class OneFileTest: TestBase
    {
        [Fact]
        public void Parse_returns_parsed_object()
        {
            var json = OneFile.Parse(GetBinaryFixture("blob", "bin"), TestData.Password);
            Assert.NotNull(json["i"]);
            Assert.NotNull(json["c"]);
        }

        [Fact]
        public void Parse_throws_on_no_content()
        {
            VerifyThrowsParseError(() => Parse("too short".ToBytes()), "too short");
        }

        [Fact]
        public void Parse_throws_on_invalid_signature()
        {
            VerifyThrowsParseError(() => ParsePad("invalid!"), "signature");
        }

        [Fact]
        public void Parse_throws_unencrypted_content()
        {
            VerifyThrowsUnsupportedFeature(() => ParsePad("onefile1"+ "\x05"), "Unencrypted");
        }

        [Fact]
        public void Parse_throws_on_invalid_checksum_type()
        {
            VerifyThrowsParseError(() => ParsePad("onefile1\x07" + "\x13"), "checksum");
        }

        [Fact]
        public void Parse_throws_on_invalid_content_length()
        {
            var lengths = new[] {new byte[] {0, 0, 0, 0x80}, new byte[] {0xFF, 0xFF, 0xFF, 0xFF}};
            foreach (var i in lengths)
                VerifyThrowsParseError(() => ParsePad("onefile1\x07\x01".ToBytes().Concat(i).ToArray()), "negative");
        }

        [Fact]
        public void Parse_throws_on_invalid_checksum()
        {
            VerifyThrowsParseError(() => ParsePad("onefile1\x07\x01\x01\x00\x00\x00" + "invalid checksum" + "!"),
                                   "Checksum");
        }

        [Fact]
        public void Parse_throws_on_too_short_content()
        {
            VerifyThrowsParseError(() => ParsePad("onefile1\x07\x01\x02\x00\x00\x00" + "invalid checksum" + "!"),
                                   "too short");
        }

        [Fact]
        public void Decrypt_throws_on_no_content()
        {
            VerifyThrowsParseError(() => Decrypt("too short".ToBytes()), "too short");
        }

        [Fact]
        public void Decrypt_throws_on_invalid_signature()
        {
            VerifyThrowsParseError(() => DecryptPad("invalid!"), "signature");
        }

        [Fact]
        public void Decrypt_throws_on_unsupported_sha1_kdf()
        {
            VerifyThrowsUnsupportedFeature(() => DecryptPad("gsencst1\x00" + "\x01"), "SHA-1");
        }

        [Fact]
        public void Decrypt_throws_on_unsupported_invalid_kdf()
        {
            VerifyThrowsParseError(() => DecryptPad("gsencst1\x00" + "\x05"), "KDF/encryption type");
        }

        [Fact]
        public void Decrypt_throws_on_invalid_iteration_count()
        {
            var iterations = new[] {new byte[] {0, 0, 0, 0}, new byte[] {0, 0x08, 0, 1}};
            foreach (var i in iterations)
                VerifyThrowsParseError(() => DecryptPad("gsencst1\x00\x02".ToBytes().Concat(i).ToArray()),
                                       "iteration count");
        }

        [Fact]
        public void Decrypt_throws_on_too_short_salt()
        {
            VerifyThrowsParseError(() => DecryptPad("gsencst1\x00\x02\x00\x10\x00\x00\x10" + "salt..."), "too short");
        }

        [Fact]
        public void Decrypt_throws_on_too_short_extra()
        {
            VerifyThrowsParseError(
                () => DecryptPad("gsencst1\x10\x02\x00\x10\x00\x00\x10saltsaltsaltsalt" + "extra..."),
                "too short");
        }

        [Fact]
        public void Decompress_returns_decompressed_data()
        {
            // Generated with bash
            // $ echo -n decompressed | gzip -c - | base64
            Assert.Equal("decompressed".ToBytes(),
                         OneFile.Decompress("H4sIANRVH1oAA0tJTc7PLShKLS5OTQEACojeBQwAAAA=".Decode64()));
        }

        [Fact]
        public void ParseJson_returns_parsed_json()
        {
            Assert.NotNull(OneFile.ParseJson("{}".ToBytes()));
        }

        [Fact]
        public void ParseJson_throws_on_invalid_json()
        {
            VerifyThrowsParseError(() => OneFile.ParseJson("}{".ToBytes()), "Corrupted");
        }

        //
        // Helpers
        //

        private static void ParsePad(string content)
        {
            ParsePad(content.ToBytes());
        }

        private static void ParsePad(byte[] content)
        {
            Parse(Pad(content, 30));
        }

        private static void Parse(byte[] content)
        {
            OneFile.Parse(content, "password");
        }

        private static void DecryptPad(string content)
        {
            DecryptPad(content.ToBytes());
        }

        private static void DecryptPad(byte[] content)
        {
            Decrypt(Pad(content, 15));
        }

        private static void Decrypt(byte[] content)
        {
            OneFile.Decrypt(content, "password");
        }

        private static byte[] Pad(byte[] content, int minLength)
        {
            if (content.Length >= minLength)
                return content;

            return content.Concat(new byte[minLength - content.Length]).ToArray();
        }

        void VerifyThrowsParseError(Action action, string partialMessage)
        {
            var e = Assert.Throws<ClientException>(action);
            Assert.Equal(ClientException.FailureReason.ParseError, e.Reason);
            Assert.Contains(partialMessage, e.Message);

        }

        void VerifyThrowsUnsupportedFeature(Action action, string partialMessage)
        {
            var e = Assert.Throws<ClientException>(action);
            Assert.Equal(ClientException.FailureReason.UnsupportedFeature, e.Reason);
            Assert.Contains(partialMessage, e.Message);

        }
    }
}
