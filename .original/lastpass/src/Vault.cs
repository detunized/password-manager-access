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
                var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));

                var key = encryptionKey;
                var rsaKey = new RSAParameters();

                foreach (var i in chunks)
                {
                    switch (i.Id)
                    {
                    case "ACCT":
                        accounts.Add(ParserHelper.Parse_ACCT(i, key));
                        break;
                    case "PRIK":
                        rsaKey = ParserHelper.Parse_PRIK(i, encryptionKey);
                        break;
                    case "SHAR":
                        key = ParserHelper.Parse_SHAR(i, encryptionKey, rsaKey);
                        break;
                    }
                }

                Accounts = accounts.ToArray();
            });
        }

        public Account[] Accounts { get; private set; }
    }
}