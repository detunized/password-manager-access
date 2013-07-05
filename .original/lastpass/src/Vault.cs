using System;
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

        public static byte[] MakeKey(string username, string password, int iterationCount)
        {
            return FetcherHelper.MakeKey(username, password, iterationCount);
        }

        public Account DecryptAccount(EncryptedAccount encryptedAccount, string username, string password)
        {
            return DecryptAccount(encryptedAccount,
                                  MakeKey(username, password, _keyIterationCount));
        }

        public Account DecryptAccount(EncryptedAccount encryptedAccount, byte[] encryptionKey)
        {
            return new Account(encryptedAccount.Id,
                               ParserHelper.DecryptAes256(encryptedAccount.Name, encryptionKey),
                               ParserHelper.DecryptAes256(encryptedAccount.Username, encryptionKey),
                               ParserHelper.DecryptAes256(encryptedAccount.Password, encryptionKey),
                               encryptedAccount.Url);
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