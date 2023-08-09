// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    // TODO: Split this file
    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string AccountKey { get; set; }
        public string Domain { get; set; }
        public string Uuid { get; set; }

        //
        // Internal
        //

        internal string UserUuid { get; set; }

        // TODO: Cache this
        internal AccountKey ParsedAccountKey => OnePassword.AccountKey.Parse(AccountKey);
    }

    public class ServiceAccount
    {
        public string Token { get; set; }
    }

    // TODO: Rename to ApplicationInfo?
    public class DeviceInfo
    {
        public string Uuid { get; set; }
        public string Name { get; set; }
        public string Model { get; set; }
    }
}
