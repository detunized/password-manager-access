using System.IO;

namespace LastPass
{
    public class Parser
    {
        public static Vault Parse(Blob blob)
        {
            using (var stream = new MemoryStream(blob.Bytes, false))
            using (var reader = new BinaryReader(stream))
            {
                var chunks = ParserHelper.ExtractChunks(reader);
            }

            return new Vault();
        }
    }
}
