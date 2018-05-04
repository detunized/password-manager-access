// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace LastPass
{
    public class Vault
    {
        public static Vault Open(string username, string password, Mode mode, Ui ui)
        {
            return Create(Download(username, password, mode, ui), username, password);
        }

        // TODO: Make a test for this!
        public static Vault Create(Blob blob, string username, string password)
        {
            return new Vault(blob, blob.MakeEncryptionKey(username, password));
        }

        public static Blob Download(string username, string password, Mode mode, Ui ui)
        {
            var session = Fetcher.Login(username, password, mode, ui);
            try
            {
                return Fetcher.Fetch(session);
            }
            finally
            {
                Fetcher.Logout(session);
            }
        }

        public static string GenerateRandomClientId()
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[16];
                random.GetBytes(bytes);
                return bytes.ToHex();
            }
        }

        // TODO: Make a test for this!
        // TODO: Extract some of the code and put it some place else.
        private Vault(Blob blob, byte[] encryptionKey)
        {
            ParserHelper.WithBytes(
                blob.Bytes,
                reader =>
                {
                    var chunks = ParserHelper.ExtractChunks(reader);
                    if (!IsComplete(chunks))
                        throw new ParseException(ParseException.FailureReason.CorruptedBlob,
                                                 "Blob is truncated");

                    var privateKey = new RSAParameters();
                    if (blob.EncryptedPrivateKey != null)
                        privateKey = ParserHelper.ParseEcryptedPrivateKey(blob.EncryptedPrivateKey,
                                                                          encryptionKey);

                    Accounts = ParseAccounts(chunks, encryptionKey, privateKey);
                });
        }

        private bool IsComplete(List<ParserHelper.Chunk> chunks)
        {
            return chunks.Count > 0 && chunks.Last().Id == "ENDM" && chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        private Account[] ParseAccounts(List<ParserHelper.Chunk> chunks,
                                        byte[] encryptionKey,
                                        RSAParameters privateKey)
        {
            var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));
            SharedFolder folder = null;

            foreach (var i in chunks)
            {
                switch (i.Id)
                {
                case "ACCT":
                    var account = ParserHelper.Parse_ACCT(
                        i,
                        folder == null ? encryptionKey : folder.EncryptionKey,
                        folder);

                    if (account != null)
                        accounts.Add(account);
                    break;
                case "SHAR":
                    folder = ParserHelper.Parse_SHAR(i, encryptionKey, privateKey);
                    break;
                }
            }

            return accounts.ToArray();
        }

        public Account[] Accounts { get; private set; }
    }
}
