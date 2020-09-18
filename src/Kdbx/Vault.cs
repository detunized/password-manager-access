// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Kdbx
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string filename, string password)
        {
            return new Vault(Parser.Parse(filename, password));
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
