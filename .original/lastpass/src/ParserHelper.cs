using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LastPass
{
    static class ParserHelper
    {
        public class Chunk
        {
            public Chunk(string id, byte[] payload)
            {
                Id = id;
                Payload = payload;
            }

            public string Id { get; private set; }
            public byte[] Payload { get; private set; }
        }

        public static Dictionary<string, Chunk[]> ExtractChunks(BinaryReader reader)
        {
            var chunks = new Dictionary<string, List<Chunk>>();
            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                var chunk = ReadChunk(reader);
                if (!chunks.ContainsKey(chunk.Id))
                {
                    chunks[chunk.Id] = new List<Chunk>();
                }
                chunks[chunk.Id].Add(chunk);
            }

            return chunks.ToDictionary(i => i.Key, i => i.Value.ToArray());
        }

        // LastPass blob chunk is made up of 4-byte ID, 4-byte size and payload of that size
        // Example:
        //   0000: 'IDID'
        //   0004: 4
        //   0008: 0xDE 0xAD 0xBE 0xEF
        //   000C: --- Next chunk ---
        public static Chunk ReadChunk(BinaryReader reader)
        {
            var id = reader.ReadBytes(4).ToUtf8();
            var size = reader.ReadUInt32().FromBigEndian();
            var payload = reader.ReadBytes((int)size);

            return new Chunk(id, payload);
        }
    }
}
