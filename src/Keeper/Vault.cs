// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Keeper
{
    public static class Vault
    {
        public static Account[] Open(string username, string password, Ui ui)
        {
            return Client.OpenVault(username, password, ui, new HttpClient());
        }
    }
}
