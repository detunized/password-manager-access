// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class Client
    {
        public static Account[] OpenVault(string username, string password, ClientInfo clientInfo, Ui ui)
        {
            var blob = DownloadVault(username, password, clientInfo, ui);
            var key = blob.MakeEncryptionKey(username, password);
            return new Account[0];
        }

        //
        // Internal
        //

        internal static Blob DownloadVault(string username, string password, ClientInfo clientInfo, Ui ui)
        {
            var session = Fetcher.Login(username, password, clientInfo, ui);
            try
            {
                return Fetcher.Fetch(session);
            }
            finally
            {
                Fetcher.Logout(session);
            }
        }

        internal static Account[] ParseVault(Blob blob, byte[] encryptionKey)
        {
            return ParserHelper.WithBytes(
                blob.Bytes,
                reader =>
                {
                    var chunks = ParserHelper.ExtractChunks(reader);
                    if (!IsComplete(chunks))
                        throw new ParseException(ParseException.FailureReason.CorruptedBlob, "Blob is truncated");

                    var privateKey = new RSAParameters();
                    if (blob.EncryptedPrivateKey != null)
                        privateKey = ParserHelper.ParseEncryptedPrivateKey(blob.EncryptedPrivateKey, encryptionKey);

                    return ParseAccounts(chunks, encryptionKey, privateKey);
                });
        }

        internal static bool IsComplete(List<ParserHelper.Chunk> chunks)
        {
            return chunks.Count > 0 &&
                   chunks.Last().Id == "ENDM" &&
                   chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        internal static Account[] ParseAccounts(List<ParserHelper.Chunk> chunks,
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
    }
}
