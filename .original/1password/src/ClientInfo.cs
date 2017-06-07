// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    internal class ClientInfo
    {
        public readonly string Username;
        public readonly string Password;
        public readonly string AccountKey;
        public readonly string Uuid;

        public ClientInfo(string username, string password, string accountKey, string uuid)
        {
            Username = username;
            Password = password;
            AccountKey = accountKey;
            Uuid = uuid;
        }
    }
}
