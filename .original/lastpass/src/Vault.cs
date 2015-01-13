// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace LastPass
{
    public class Vault
    {
        public static Vault Create(string username, string password, string multifactorPassword = null)
        {
            return Create(Download(username, password, multifactorPassword), username, password);
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

        // TODO: Make a test for this!
        // TODO: Extract some of the code and put it some place else.
        private Vault(Blob blob, byte[] encryptionKey)
        {
            ParserHelper.WithBytes(blob.Bytes, reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                if (!IsComplete(chunks))
                    throw new ParseException(ParseException.FailureReason.CorruptedBlob, "Blob is truncated");

                Accounts = ParseAccounts(chunks, encryptionKey);
            });
        }

        private bool IsComplete(List<ParserHelper.Chunk> chunks)
        {
            return chunks.Count > 0 && chunks.Last().Id == "ENDM" && chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        private Account[] ParseAccounts(List<ParserHelper.Chunk> chunks, byte[] encryptionKey)
        {
            var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));
            SharedFolder folder = null;
            var rsaKey = new RSAParameters();

            foreach (var i in chunks)
            {
                switch (i.Id)
                {
                    case "ACCT":
                        var account = ParserHelper.Parse_ACCT(i,
                                                              folder == null ? encryptionKey : folder.EncryptionKey,
                                                              folder);
                        if (account != null)
                            accounts.Add(account);
                        break;
                    case "PRIK":
                        rsaKey = ParserHelper.Parse_PRIK(i, encryptionKey);
                        break;
                    case "SHAR":
                        folder = ParserHelper.Parse_SHAR(i, encryptionKey, rsaKey);
                        break;
                }
            }

            return accounts.ToArray();
        }

        public Account[] Accounts { get; private set; }
    }
}