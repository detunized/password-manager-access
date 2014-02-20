// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ParserHelperTest
    {
        [Test]
        public void ParseAccount_returns_account()
        {
            WithBlob(reader => {
                var accounts = ParserHelper.ExtractChunks(reader).Where(i => i.Id == "ACCT").ToArray();
                for (var i = 0; i < accounts.Length; ++i)
                {
                    var account = ParserHelper.Parse_ACCT(accounts[i], TestData.EncryptionKey);
                    Assert.True(account.Url.StartsWith(TestData.Accounts[i].Url));
                }
            });
        }

        [Test]
        public void ReadChunk_returns_first_chunk()
        {
            WithBlob(reader => {
                var chunk = ParserHelper.ReadChunk(reader);
                Assert.AreEqual("LPAV", chunk.Id);
                Assert.AreEqual(3, chunk.Payload.Length);
                Assert.AreEqual(11, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadChunk_reads_all_chunks()
        {
            WithBlob(reader => {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                    ParserHelper.ReadChunk(reader);

                Assert.AreEqual(reader.BaseStream.Length, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ExtractChunks_returns_all_chunks()
        {
            WithBlob(reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                var ids = chunks.Select(i => i.Id).Distinct().ToArray();
                Assert.AreEqual(TestData.ChunkIds, ids);
            });
        }

        [Test]
        public void ReadItem_returns_first_item()
        {
            WithBlob(reader => {
                var chunks = ParserHelper.ExtractChunks(reader);

                var account = chunks.Find(i => i.Id == "ACCT");
                Assert.NotNull(account);

                ParserHelper.WithBytes(account.Payload, chunkReader => {
                    var item = ParserHelper.ReadItem(chunkReader);
                    Assert.NotNull(item);
                });
            });
        }

        [Test]
        public void SkipItem_skips_empty_item()
        {
            WithHex("00000000", reader => {
                ParserHelper.SkipItem(reader);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void SkipItem_skips_non_empty_item()
        {
            WithHex("00000004DEADBEEF", reader => {
                ParserHelper.SkipItem(reader);
                Assert.AreEqual(8, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadId_returns_id()
        {
            var expectedId = "ABCD";
            ParserHelper.WithBytes(expectedId.ToBytes(), reader => {
                var id = ParserHelper.ReadId(reader);
                Assert.AreEqual(expectedId, id);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadSize_returns_size()
        {
            WithHex("DEADBEEF", reader => {
                var size = ParserHelper.ReadSize(reader);
                Assert.AreEqual(0xDEADBEEF, size);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadPayload_returns_payload()
        {
            var expectedPayload = "FEEDDEADBEEF".DecodeHex();
            var size = expectedPayload.Length;
            ParserHelper.WithBytes(expectedPayload, reader => {
                var payload = ParserHelper.ReadPayload(reader, (uint)size);
                Assert.AreEqual(expectedPayload, payload);
                Assert.AreEqual(size, reader.BaseStream.Position);
            });
        }

        [Test]
        public void DecryptAes256EcbPlain()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "8mHxIA8rul6eq72a/Gq2iw=="},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256EcbPlain(i.Value.Decode64(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256EcbBase64()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "8mHxIA8rul6eq72a/Gq2iw=="},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256EcbBase64(i.Value.ToBytes(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256CbcPlain()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX"},
                {"All your base are belong to us", "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256CbcPlain(i.Value.Decode64(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256CbcBase64()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug=="},
                {"All your base are belong to us", "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256CbcBase64(i.Value.ToBytes(), _encryptionKey));
        }

        private static void WithBlob(Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(TestData.Blob, action);
        }

        private static void WithHex(string hex, Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(hex.DecodeHex(), action);
        }

        private static readonly byte[] _encryptionKey = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();
    }
}
