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
                                    : new EncryptedAccount[] {},
                                 blob.KeyIterationCount);
            });
        }

        public Account DecryptAccount(EncryptedAccount encryptedAccount, string username, string password)
        {
            return DecryptAccount(encryptedAccount,
                                  FetcherHelper.MakeKey(username, password, _keyIterationCount));
        }

        public Account DecryptAccount(EncryptedAccount encryptedAccount, byte[] encryptionKey)
        {
            return new Account("name", "username", "password", encryptedAccount.Url);
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