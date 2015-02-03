// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
        public void Parse_PRIK_returns_private_key()
        {
            var chunk = new ParserHelper.Chunk("PRIK", TestData.Chunk_PRIK);
            var rsa = ParserHelper.Parse_PRIK(chunk, TestData.EncryptionKey);

            Assert.AreEqual(TestData.RsaD, rsa.D);
            Assert.AreEqual(TestData.RsaDP, rsa.DP);
            Assert.AreEqual(TestData.RsaDQ, rsa.DQ);
            Assert.AreEqual(TestData.RsaExponent, rsa.Exponent);
            Assert.AreEqual(TestData.RsaInverseQ, rsa.InverseQ);
            Assert.AreEqual(TestData.RsaModulus, rsa.Modulus);
            Assert.AreEqual(TestData.RsaP, rsa.P);
            Assert.AreEqual(TestData.RsaQ, rsa.Q);
        }

        [Test]
        public void Parse_SHAR_returns_folder_key_when_aes_encrypted()
        {
            var id = "id";
            var name = "name";
            var key = "0123456789012345".ToBytes();

            var items = new[] {
                MakeItem(id),
                MakeItem("rsa"),
                MakeItem(Encode64(EncryptAes256(name, key))),
                MakeItem("skipped"),
                MakeItem("skipped"),
                MakeItem(EncryptAes256(key.ToHex(), TestData.EncryptionKey)),
            };

            var folder = ParserHelper.Parse_SHAR(MakeChunk("SHAR", items),
                                                 TestData.EncryptionKey,
                                                 new RSAParameters());

            Assert.AreEqual(id, folder.Id);
            Assert.AreEqual(name, folder.Name);
            Assert.AreEqual(key, folder.EncryptionKey);
        }

        [Test]
        public void Parse_PRIK_throws_on_invalid_chunk()
        {
            var chunk = new ParserHelper.Chunk("PRIK", "".ToBytes());
            var e = Assert.Throws<ParseException>(() => ParserHelper.Parse_PRIK(chunk, TestData.EncryptionKey));
            Assert.AreEqual(ParseException.FailureReason.CorruptedBlob, e.Reason);
            Assert.AreEqual("Failed to decrypt private key", e.Message);
        }

        [Test]
        public void ParseSecureNoteServer_parses_all_parameters()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            ParserHelper.ParseSecureNoteServer("NoteType:type\nHostname:url\nUsername:username\nPassword:password",
                                               ref type,
                                               ref url,
                                               ref username,
                                               ref password);

            Assert.AreEqual("type", type);
            Assert.AreEqual("url", url);
            Assert.AreEqual("username", username);
            Assert.AreEqual("password", password);
        }

        [Test]
        public void ParseSecureNoteServer_handles_extra_colons()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            ParserHelper.ParseSecureNoteServer("NoteType:type:type\nHostname:url:url\nUsername:username:username\nPassword:password:password",
                                               ref type,
                                               ref url,
                                               ref username,
                                               ref password);

            Assert.AreEqual("type:type", type);
            Assert.AreEqual("url:url", url);
            Assert.AreEqual("username:username", username);
            Assert.AreEqual("password:password", password);
        }

        [Test]
        public void ParseSecureNoteServer_skips_invalid_lines()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            ParserHelper.ParseSecureNoteServer("Something:Else\nHostname\nUsername:\n:\n::\n\n",
                                               ref type,
                                               ref url,
                                               ref username,
                                               ref password);

            Assert.AreEqual("", type);
            Assert.AreEqual("", url);
            Assert.AreEqual("", username);
            Assert.AreEqual("", password);
        }

        [Test]
        public void ParseSecureNoteServer_does_not_modify_missing_parameters()
        {
            string type = "type";
            string url = "url";
            string username = "username";
            string password = "password";
            ParserHelper.ParseSecureNoteServer("", ref type, ref url, ref username, ref password);

            Assert.AreEqual("type", type);
            Assert.AreEqual("url", url);
            Assert.AreEqual("username", username);
            Assert.AreEqual("password", password);
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
        public void DecryptAes256Plain_with_default_value()
        {
            var defVal = "ohai!";
            var plaintext = ParserHelper.DecryptAes256Plain("not a valid ciphertext".ToBytes(),
                                                            _encryptionKey,
                                                            defVal);
            Assert.AreEqual(defVal, plaintext);
        }

        [Test]
        public void DecryptAes256Base64_with_default_value()
        {
            var defVal = "ohai!";
            var plaintext = ParserHelper.DecryptAes256Base64("bm90IGEgdmFsaWQgY2lwaGVydGV4dA==".ToBytes(),
                                                             _encryptionKey,
                                                             defVal);
            Assert.AreEqual(defVal, plaintext);
        }

        [Test]
        public void DecryptAes256Plain()
        {
            var tests = new[,] {
                {"", ""},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="},
                {"All your base are belong to us", "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=="}
            };

            for (var i = 0; i < tests.Rank; ++i)
                Assert.AreEqual(tests[i, 0], ParserHelper.DecryptAes256Plain(tests[i, 1].Decode64(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256Base64()
        {
            var tests = new[,] {
                {"", ""},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="},
                {"All your base are belong to us", "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="}
            };

            for (var i = 0; i < tests.Rank; ++i)
                Assert.AreEqual(tests[i, 0], ParserHelper.DecryptAes256Base64(tests[i, 1].ToBytes(), _encryptionKey));
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

        //
        // Helpers
        //

        private static void WithBlob(Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(TestData.Blob, action);
        }

        private static void WithHex(string hex, Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(hex.DecodeHex(), action);
        }

        private static byte[] MakeItem(string payload)
        {
            return MakeItem(payload.ToBytes());
        }

        private static byte[] MakeItem(byte[] payload)
        {
            var sizeBits = BitConverter.GetBytes(payload.Length);
            if (BitConverter.IsLittleEndian)
                sizeBits = sizeBits.Reverse().ToArray();

            return sizeBits.Concat(payload).ToArray();
        }

        private static ParserHelper.Chunk MakeChunk(string id, byte[][] items)
        {
            IEnumerable<IEnumerable<byte>> itemsAsEnumerable = items;
            var chained = itemsAsEnumerable.Aggregate((chain, i) => chain.Concat(i));
            return new ParserHelper.Chunk(id, chained.ToArray());
        }

        private static string Encode64(byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        private static byte[] EncryptAes256(string data, byte[] encryptionKey)
        {
            return EncryptAes256(data.ToBytes(), encryptionKey);
        }

        private static byte[] EncryptAes256(byte[] data, byte[] encryptionKey)
        {
            using (var aes = new AesManaged { KeySize = 256, Key = encryptionKey, Mode = CipherMode.ECB })
            using (var encryptor = aes.CreateEncryptor())
            using (var encryptedStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(encryptedStream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return encryptedStream.ToArray();
            }
        }

        private static readonly byte[] _encryptionKey = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();
    }
}
