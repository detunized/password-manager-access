using System.IO;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(Blob blob)
        {
            ParserHelper.WithBytes(blob.Bytes, reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
            });

            return new Vault();
        }

        private Vault()
        {
        }
    }
}