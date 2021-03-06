// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ParserTest
    {
        [Fact]
        public void ParseAccount_returns_account()
        {
            WithBlob(reader => {
                var accounts = Parser.ExtractChunks(reader).Where(i => i.Id == "ACCT").ToArray();
                for (var i = 0; i < accounts.Length; ++i)
                {
                    var account = Parser.Parse_ACCT(accounts[i], TestData.EncryptionKey);
                    Assert.StartsWith(TestData.Accounts[i].Url, account.Url);
                }
            });
        }

        [Fact]
        public void ParseEncryptedPrivateKey_returns_private_key()
        {
            var rsa = Parser.ParseEncryptedPrivateKey(TestData.EncryptedPrivateKey,
                                                           TestData.EncryptionKey);

            Assert.Equal(TestData.RsaD, rsa.D);
            Assert.Equal(TestData.RsaDP, rsa.DP);
            Assert.Equal(TestData.RsaDQ, rsa.DQ);
            Assert.Equal(TestData.RsaExponent, rsa.Exponent);
            Assert.Equal(TestData.RsaInverseQ, rsa.InverseQ);
            Assert.Equal(TestData.RsaModulus, rsa.Modulus);
            Assert.Equal(TestData.RsaP, rsa.P);
            Assert.Equal(TestData.RsaQ, rsa.Q);
        }

        [Fact]
        public void ParseEncryptedPrivateKey_throws_on_invalid_chunk()
        {
            Exceptions.AssertThrowsInternalError(
                () => Parser.ParseEncryptedPrivateKey("", TestData.EncryptionKey),
                "Failed to decrypt private key");
        }

        [Fact]
        public void ParseSecureNoteServer_parses_all_parameters()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            Parser.ParseSecureNoteServer("NoteType:type\nHostname:url\nUsername:username\nPassword:password",
                                         ref type,
                                         ref url,
                                         ref username,
                                         ref password);

            Assert.Equal("type", type);
            Assert.Equal("url", url);
            Assert.Equal("username", username);
            Assert.Equal("password", password);
        }

        [Fact]
        public void ParseSecureNoteServer_handles_extra_colons()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            Parser.ParseSecureNoteServer("NoteType:type:type\nHostname:url:url\nUsername:username:username\nPassword:password:password",
                                         ref type,
                                         ref url,
                                         ref username,
                                         ref password);

            Assert.Equal("type:type", type);
            Assert.Equal("url:url", url);
            Assert.Equal("username:username", username);
            Assert.Equal("password:password", password);
        }

        [Fact]
        public void ParseSecureNoteServer_skips_invalid_lines()
        {
            string type = "";
            string url = "";
            string username = "";
            string password = "";
            Parser.ParseSecureNoteServer("Something:Else\nHostname\nUsername:\n:\n::\n\n",
                                         ref type,
                                         ref url,
                                         ref username,
                                         ref password);

            Assert.Equal("", type);
            Assert.Equal("", url);
            Assert.Equal("", username);
            Assert.Equal("", password);
        }

        [Fact]
        public void ParseSecureNoteServer_does_not_modify_missing_parameters()
        {
            string type = "type";
            string url = "url";
            string username = "username";
            string password = "password";
            Parser.ParseSecureNoteServer("", ref type, ref url, ref username, ref password);

            Assert.Equal("type", type);
            Assert.Equal("url", url);
            Assert.Equal("username", username);
            Assert.Equal("password", password);
        }

        [Fact]
        public void MakeAccountPath_returns_none_when_group_is_null_or_blank_and_not_in_shared_folder()
        {
            Assert.Equal("(none)", Parser.MakeAccountPath(null, null));
            Assert.Equal("(none)", Parser.MakeAccountPath("", null));
        }

        [Fact]
        public void MakeAccountPath_returns_shared_folder_name_when_group_is_null_or_blank()
        {
            var folder = new SharedFolder("id", "folder", null);

            Assert.Equal("folder", Parser.MakeAccountPath(null, folder));
            Assert.Equal("folder", Parser.MakeAccountPath("", folder));
        }

        [Fact]
        public void MakeAccountPath_combines_shared_folder_and_group()
        {
            var folder = new SharedFolder("id", "folder", null);

            Assert.Equal("folder\\group", Parser.MakeAccountPath("group", folder));
        }

        [Fact]
        public void MakeAccountPath_returns_group_when_not_in_shared_folder()
        {
            Assert.Equal("group", Parser.MakeAccountPath("group", null));
        }

        [Fact]
        public void ReadChunk_returns_first_chunk()
        {
            WithBlob(reader => {
                var chunk = Parser.ReadChunk(reader);
                Assert.Equal("LPAV", chunk.Id);
                Assert.Equal(3, chunk.Payload.Length);
                Assert.Equal(11, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void ReadChunk_reads_all_chunks()
        {
            WithBlob(reader => {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                    Parser.ReadChunk(reader);

                Assert.Equal(reader.BaseStream.Length, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void ExtractChunks_returns_all_chunks()
        {
            WithBlob(reader => {
                var chunks = Parser.ExtractChunks(reader);
                var ids = chunks.Select(i => i.Id).Distinct().ToArray();
                Assert.Equal(TestData.ChunkIds, ids);
            });
        }

        [Fact]
        public void ReadItem_returns_first_item()
        {
            WithBlob(reader => {
                var chunks = Parser.ExtractChunks(reader);
                var account = chunks.Find(i => i.Id == "ACCT");

                account.Payload.Open(chunkReader => {
                    var item = Parser.ReadItem(chunkReader);
                    Assert.NotNull(item);
                });
            });
        }

        [Fact]
        public void SkipItem_skips_empty_item()
        {
            WithHex("00000000", reader => {
                Parser.SkipItem(reader);
                Assert.Equal(4, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void SkipItem_skips_non_empty_item()
        {
            WithHex("00000004DEADBEEF", reader => {
                Parser.SkipItem(reader);
                Assert.Equal(8, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void ReadId_returns_id()
        {
            var expectedId = "ABCD";
            expectedId.ToBytes().Open(reader => {
                var id = Parser.ReadId(reader);
                Assert.Equal(expectedId, id);
                Assert.Equal(4, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void ReadSize_returns_size()
        {
            WithHex("DEADBEEF", reader => {
                var size = Parser.ReadSize(reader);
                Assert.Equal(0xDEADBEEF, size);
                Assert.Equal(4, reader.BaseStream.Position);
            });
        }

        [Fact]
        public void ReadPayload_returns_payload()
        {
            var expectedPayload = "FEEDDEADBEEF".DecodeHex();
            var size = expectedPayload.Length;
            expectedPayload.Open(reader => {
                var payload = Parser.ReadPayload(reader, (uint)size);
                Assert.Equal(expectedPayload, payload);
                Assert.Equal(size, reader.BaseStream.Position);
            });
        }

        //
        // Helpers
        //

        private static void WithBlob(Action<BinaryReader> action)
        {
            TestData.Blob.Open(action);
        }

        private static void WithHex(string hex, Action<BinaryReader> action)
        {
            hex.DecodeHex().Open(action);
        }
    }
}
