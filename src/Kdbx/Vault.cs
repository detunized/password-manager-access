// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;

namespace PasswordManagerAccess.Kdbx
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string filename, string password, string keyfile = null)
        {
            return new Vault(Parser.Parse(filename, password, keyfile));
        }

        public static Vault Open(byte[] input, string password, byte[] keyfile = null)
        {
            return new Vault(Parser.Parse(input, password, keyfile));
        }

        public static Vault Open(Stream input, string password, Stream keyfile = null)
        {
            return new Vault(Parser.Parse(input, password, keyfile));
        }

        //
        // Internal
        //

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
