// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.ZohoVault
{
    public class Credentials
    {
        public string Username { get; }
        public string Password { get; }
        public string Passphrase { get; }

        public Credentials(string username, string password, string passphrase)
        {
            Username = username;
            Password = password;
            Passphrase = passphrase;
        }
    }
}
