// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    public class Vault
    {
        public static Vault Open(string username, string password)
        {
            using var transport = new RestTransport();
            return Open(username, password, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username, string password, IRestTransport transport)
        {
            Client.OpenVault(username, password, transport);
            return new Vault();
        }
    }
}