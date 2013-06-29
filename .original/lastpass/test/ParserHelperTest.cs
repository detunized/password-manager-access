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
            using (var stream = new MemoryStream(TestData.Blob, false))
            using (var reader = new BinaryReader(stream))
            {
                var chunk1 = ParserHelper.ReadChunk(reader);
                Assert.AreEqual("LPAV", chunk1.Id);
                Assert.AreEqual(1, chunk1.Payload.Length);
                Assert.AreEqual(9, reader.BaseStream.Position);
            }
        }

        [Test]
        public void ReadChunk_reads_all_chunks()
        {
            using (var stream = new MemoryStream(TestData.Blob, false))
            using (var reader = new BinaryReader(stream))
            {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    ParserHelper.ReadChunk(reader);
                }

                Assert.AreEqual(reader.BaseStream.Length, reader.BaseStream.Position);
            }
        }

        [Test]
        public void ExtractChunks_returns_all_chunks()
        {
            using (var stream = new MemoryStream(TestData.Blob, false))
            using (var reader = new BinaryReader(stream))
            {
                var chunks = ParserHelper.ExtractChunks(reader);
                Assert.AreEqual(20, chunks.Keys.Count);
                Assert.AreEqual(TestData.ChunkIds, chunks.Keys);
            }
        }
    }
}
