// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    public class ClientInfo
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string AccountKey { get; set; }
        public string Uuid { get; set; }
        public string Domain { get; set; } // Use Region.ToDomain to convert from Region
        public string DeviceName { get; set; }
        public string DeviceModel { get; set; }

        internal AccountKey ParsedAccountKey
        {
            get
            {
                if (_parsedAccountKey == null)
                    _parsedAccountKey = OnePassword.AccountKey.Parse(AccountKey);

                return _parsedAccountKey;
            }
        }

        private AccountKey _parsedAccountKey;
    }
}
