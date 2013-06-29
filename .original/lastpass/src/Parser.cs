using System.IO;

namespace LastPass
{
    public class Parser
    {
        public Parser(Fetcher.Blob blob)
        {
            using (var stream = new MemoryStream(blob.Bytes, false))
            using (var reader = new BinaryReader(stream))
            {
                var chunks = ParserHelper.ExtractChunks(reader);
            }
        }
    }
}
