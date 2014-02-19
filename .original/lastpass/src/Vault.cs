// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(string username, string password, string multifactorPassword = null)
        {
            return Create(Download(username, password, multifactorPassword));
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

        // TODO: Make a test for this!
        public static Vault Create(Blob blob, string username, string password)
        {
            return new Vault(blob, blob.MakeEncryptionKey(username, password));
        }

        public static Blob Download(string username, string password, string multifactorPassword = null)
        {
            return Fetcher.Fetch(Fetcher.Login(username, password, multifactorPassword));
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

        // TODO: Make a test for this!
        private Vault(Blob blob, byte[] encryptionKey)
        {
            ParserHelper.WithBytes(blob.Bytes, reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                Accounts = chunks.ContainsKey("ACCT")
                    ? chunks["ACCT"].Select(ParserHelper.ParseAccount).ToArray()
                    : new Account[] { };
            });

            DecryptAllAccounts(Account.Field.Name |
                               Account.Field.Username |
                               Account.Field.Password |
                               Account.Field.Group,
                               encryptionKey);
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