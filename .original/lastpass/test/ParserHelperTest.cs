using System;
using System.IO;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ParserHelperTest
    {
        [Test]
        public void ReadChunk_returns_first_chunk()
        {
            WithBlob(reader => {
                var chunk = ParserHelper.ReadChunk(reader);
                Assert.AreEqual("LPAV", chunk.Id);
                Assert.AreEqual(2, chunk.Payload.Length);
                Assert.AreEqual(10, reader.BaseStream.Position);
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
                Assert.AreEqual(21, chunks.Keys.Count);
                Assert.AreEqual(TestData.ChunkIds, chunks.Keys);
            });
        }

        [Test]
        public void ReadItems_returns_first_item()
        {
            WithBlob(reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                Assert.AreEqual(100, chunks["ACCT"].Length);

                WithBytes(chunks["ACCT"][0].Payload, chunkReader => {
                    var item = ParserHelper.ReadItem(chunkReader);
                    Assert.NotNull(item);
                });
            });
        }

        private static void WithBlob(Action<BinaryReader> action)
        {
            WithBytes(TestData.Blob, action);
        }

        private static void WithBytes(byte[] bytes, Action<BinaryReader> action)
        {
            using (var stream = new MemoryStream(bytes, false))
            using (var reader = new BinaryReader(stream))
                action(reader);
        }
    }
}
