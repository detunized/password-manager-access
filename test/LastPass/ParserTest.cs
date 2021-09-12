// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ParserTest
    {
        [Fact]
        public void Parse_SHAR_returns_parsed_chunk()
        {
            var chunk = new Parser.Chunk("SHAR", "AAAACTM5OTUzOTMwMQAAAgAyYWU3MmY0ZmNiNDY0YmU1ZjNmYjczMGEzNjliM2MyMTM0MTZhYmYwMzU3YjlhM2ZiODM5ZWE3NTNhMzJlOWE5MTBlMGZmYmRkOTFhN2FkYzIxMTU0ZmYwMmE4MmU0YTlhYTIwZGQ5OTMwMzFlODU4YjQ3YjU4MWExNGQwMTUwZTE3Mjc0M2NlYzkwZTc4ZmNmYWY0NGFmNmMxYzJmOTc3MGUyZWIzMTU1NGM5YjI0OWM2MjU1MmI0NzQzM2VmZjdiMTJhNTAyODc1NGM3NWExNjIzMTFkYjQyNDFjMjBhMTRhOTRkMjA4MzE1MDIwZjM5ZTMyY2VlNDU4N2E1YmMxMjRlZjk2OWJhZDFiMzUwMDY0MmM5ZTI2YWUyOTVkZDU1ODcwNTljMGZjNDVjYjAzZGExNmM5MjM5ODllNDVhYmQ0NDhlYWU2ODc1YmU0NDJjOTM4MjllYThmNTNlNzg2YThmMTQ2ZjE4MDkwYzlhNzc3NTE0NTg2N2Q2ZDhkMDFkZWRmYjYwYmFkMGNiYTJhZWY0MGE0MDU3ZTE3MzJiNTUyYmUyNTMzNGRkNzQ3ODYwOTY2ZTJlM2U4MTkwMjE5MjRlY2JmYjQ2NjQxNzY2Nzk1NzJiM2RiZWI5YjcwYTg5NTg4MGVhNGQ1NWM3YzkyMmYyNTU0ZTg0M2YxNDdjMgAAAEYhRk9RRnY0NFZRRUVRRnhaZ25MRmtlUT09fENRc2pLMzZsaTZlTTVBdEozc0lDVzF6TWV1VVhhNGhxUHNwRnBDVUYxMTg9AAAAATAAAAABMQAAAAAAAAABMAAAAAExAAAAAA==".Decode64());
            var key = "p8utF7ZB8yD06SrtrD4hsdvEOiBU1Y19cr2dhG9DWZg=".Decode64();
            var rsa = new RSAParameters
            {
                Exponent = "EQ==".Decode64(),
                Modulus = "tYvqQolaqyi52qwan0Kt1Ybz9yDWuDtSMSrgvfLsWJ1mTR/Xy95k+giaxCNoXLkJhLZsV31AcmP0UcsaabXBOaxcLODkzimyNFTFTS5j8uG3cddVTEC+f804RV6B8qD/uOIDX4y+q6z9o1w9k1hDqoBvNNSIWhlBGOa4XTJbEo+ogIMZAskypXsAP7uL9oswqBVhRXUmiAwJKvz87J1PASkokaI3l87vwwValdXPMX7XJZ7zuHL0RjsR27aEomVMJKWAs0ZySQdZO18ghw4N4O1/2Sf1xnCLPbdnrDvzH8OYd2NsZbxqUonUtGTMwqXZcX1sNbWB+KQmA4egwRxU1w==".Decode64(),
                P = "22JmIOSSbJ3B4kSOI8U1v/bmL6SQ26mL8qVG5KdnWEvpD8iXmuASC6Ban6T8lXmwbAaRjE8shENQre6Zr2301t/LzZmH10PrcYreX7igfjBD6MUN5qm9eEvE7RavusIyUeZri1cDbbXgzaUJL0HTYAUUzcy5e4K9IJVDdkvjoG0=".Decode64(),
                Q = "09jTR1viCvjgSdfsh+EHVq4yPcGPGGn7ZyqUZYIwtpHmlH8BINs2l18TKH3j60FUiZVPG91cYYBLAUou+IY9o5x4vSMCCYpR+YNUcSCeOhUuHEdDBijcnUiW79/8eukRBzrWNblp15iT/mQJaDsEn61bzylmomQrVftJtLs4p9M=".Decode64(),
                DP = "M56unlPmN6ymFx8wgOMbtLKQg65AM69sORfUcglFfi/6mk1Q2SWp5J4zcNuGucJHoPJ8mXwKeXlAKOzY3fvBI3/zt+fjui4ZR+Rwjv5D4XTErz1srr6G7yDjCpvtHOJmMWNkmUGmdCrLe65cg5cEjxBBIV1Y0cRovF9bKuSuB6E=".Decode64(),
                DQ = "fJ2pdUUbjfvPOn8DmzkTYCo7q9tFHWuE00Y5LKbvenPxDA55ImLU0YM4civve1ObI8E9l+ufwOIOAMI5v14GJAGwb0HE9o2ZodTIQouoXmbP1GYnbQj6PmbvX+0rGx+vqeZf414CBlnAd4YjprlOA5Mm8lSWueCR9leUxKpdj+U=".Decode64(),
                InverseQ = "CDC3/yIrcTf1DGxQny7Jr1/mO+UQG/PeraOAZc99VonwGszLHuv/6O8UyyPp4QpzSNZbu5fpQ6qWE5zhXChP6xTL6bhkRfNzpgRu0aCJANUGX2S9IsNmJLwvFEvocVP0WkVsLtszfUuWAMjF2Ah9pFl6CW6WCbwwPW7Ax6Q5uCA=".Decode64(),
                D = "dXimo4YNfc8O2Mm234V/iiolY6vWOvk1Lt+CXMpcsc9CMedtg+pBVn4JyjUHSw5Rc/2RZcmEDcg0rWVNU3WbJVFo0b6yKwvrx4IlUA71YOxnpAPNx+2ocNAVWg/5uxzhs92JtkwC544Nh9JF9e3RblMax9TQssUMAQ3Clqgcz8VG8JkYBUXicwTFgDkJnV+2emdwn5F7ABmepGEZUQNlvIU3ezNQJUfXUWITd4+rPZoohk30pdOvCTn0h4raFl0eP8ZEzNReIkZs8A2c9/6gzgSawMdgJU6IXoaG7fOYtMt0Rsp96+fqxmf2jPj1S0j2TnGzR0KMC3lxhqIP8NLa+Q==".Decode64(),
            };

            var parsed = Parser.Parse_SHAR(chunk, key, rsa);

            Assert.Equal("399539301", parsed.Id);
            Assert.Equal("Shared-SharedTest", parsed.Name);
            Assert.Equal("GnqKMOEwMH+wET2Xmhl2oD8R1Qohirg0hwidTlrPFvc=".Decode64(), parsed.EncryptionKey);
        }

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
