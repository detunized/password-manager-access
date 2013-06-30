using System.IO;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(Blob blob)
        {
            using (var stream = new MemoryStream(blob.Bytes, false))
            using (var reader = new BinaryReader(stream))
            {
                var chunks = ParserHelper.ExtractChunks(reader);
            }

            return new Vault();
        }

        private Vault()
        {
        }
    }
}