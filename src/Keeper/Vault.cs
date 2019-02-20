// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Keeper
{
    public class Vault
    {
        public static void Open(string username, string password)
        {
            Client.OpenVault(username, password, new HttpClient());
        }
    }
}
