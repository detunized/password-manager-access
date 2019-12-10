// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    internal class ClientInfo
    {
        public readonly string Username;
        public readonly string Password;
        public readonly AccountKey AccountKey;
        public readonly string Uuid;
        public readonly string Domain;

        public ClientInfo(string username,
                          string password,
                          string accountKey,
                          string uuid,
                          string domain)
        {
            Username = username;
            Password = password;
            AccountKey = AccountKey.Parse(accountKey);
            Uuid = uuid;
            Domain = domain;
        }
    }
}
