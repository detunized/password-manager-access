using System.Linq;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(string username, string password)
        {
            return Create(Download(username, password));
        }

        public static Vault Create(Blob blob)
        {
            return ParserHelper.WithBytes(blob.Bytes, reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                return new Vault(chunks.ContainsKey("ACCT")
                                    ? chunks["ACCT"].Select(ParserHelper.ParseAccount).ToArray()
                                    : new Account[] {},
                                 blob.KeyIterationCount);
            });
        }

        public static Blob Download(string username, string password)
        {
            return Fetcher.Fetch(Fetcher.Login(username, password));
        }

        public byte[] MakeKey(string username, string password)
        {
            return FetcherHelper.MakeKey(username, password, _keyIterationCount);
        }

        public Account GetAccount(string id)
        {
            return Accounts.First(i => i.Id == id);
        }

        public void DecryptAllAccounts(Account.Field fields, string username, string password)
        {
            DecryptAllAccounts(fields, MakeKey(username, password));
        }

        public void DecryptAllAccounts(Account.Field fields, byte[] encryptionKey)
        {
            foreach (var i in Accounts)
                i.Decrypt(fields, encryptionKey);
        }

        private Vault(Account[] accounts, int keyIterationCount)
        {
            Accounts = accounts;
            _keyIterationCount = keyIterationCount;
        }

        public Account[] Accounts { get; private set; }
        private readonly int _keyIterationCount;
    }
}