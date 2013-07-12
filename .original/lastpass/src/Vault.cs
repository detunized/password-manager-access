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

        public Account DecryptAccount(EncryptedAccount encryptedAccount, string username, string password)
        {
            return DecryptAccount(encryptedAccount, MakeKey(username, password));
        }

        public Account DecryptAccount(EncryptedAccount encryptedAccount, byte[] encryptionKey)
        {
            return new Account(encryptedAccount.Id,
                               encryptedAccount.Name.Decrypt(encryptionKey),
                               encryptedAccount.Username.Decrypt(encryptionKey),
                               encryptedAccount.Password.Decrypt(encryptionKey),
                               encryptedAccount.Url,
                               encryptedAccount.Group.Decrypt(encryptionKey));
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