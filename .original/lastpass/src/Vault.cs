using System.Linq;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(Blob blob)
        {
            return ParserHelper.WithBytes(blob.Bytes, reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                return new Vault(chunks.ContainsKey("ACCT")
                                 ? chunks["ACCT"].Select(ParserHelper.ParseAccount).ToArray()
                                 : new Account[] {});
            });
        }

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }

        public Account[] Accounts { get; private set; }
    }
}