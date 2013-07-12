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
                                    : new EncryptedAccount[] {},
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

        public void DecryptAllAccounts(EncryptedAccount.Field fields, string username, string password)
        {
            DecryptAllAccounts(fields, MakeKey(username, password));
        }

        public void DecryptAllAccounts(EncryptedAccount.Field fields, byte[] encryptionKey)
        {
            foreach (var i in EncryptedAccounts)
                i.Decrypt(fields, encryptionKey);
        }

        private Vault(EncryptedAccount[] encryptedAccounts, int keyIterationCount)
        {
            EncryptedAccounts = encryptedAccounts;
            _keyIterationCount = keyIterationCount;
        }

        public EncryptedAccount[] EncryptedAccounts { get; private set; }
        private readonly int _keyIterationCount;
    }
}