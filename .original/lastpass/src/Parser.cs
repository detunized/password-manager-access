using System.IO;
using System.Text;

namespace LastPass
{
    public class Parser
    {
        public Parser(Fetcher.Blob blob)
        {
            using (var stream = new MemoryStream(blob.Bytes, false))
            using (var reader = new BinaryReader(stream))
            {
                ExtractChunks(reader);
            }
        }

        private void ExtractChunks(BinaryReader reader)
        {
            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                ReadChunk(reader);
            }
        }

        // LastPass blob chunk is made up of 4-byte ID, 4-byte size and payload of that size
        // Example:
        //   0000: 'IDID'
        //   0004: 4
        //   0008: 0xDE 0xAD 0xBE 0xEF
        //   000C: --- Next chunk ---
        private void ReadChunk(BinaryReader reader)
        {
            var id = Encoding.UTF8.GetString(reader.ReadBytes(4));
            var size = reader.ReadUInt32().FromBigEndian();
            var payload = reader.ReadBytes((int)size);
        }
    }
}
