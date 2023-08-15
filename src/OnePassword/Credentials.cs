// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }

        public string AccountKey
        {
            get => _accountKey;
            set
            {
                _accountKey = value;
                _parsedAccountKey = null;
            }
        }

        public string Domain { get; set; }
        public string DeviceUuid { get; set; }

        //
        // Internal
        //

        // Not a valid user UUID used a sentinel value
        internal const string IgnoreUserUuid = "ignore-user-uuid";

        internal string UserUuid { get; set; }
        internal string SrpX { get; set; }
        internal AesKey Key { get; set; }

        internal AccountKey ParsedAccountKey
        {
            get
            {
                if (_parsedAccountKey == null)
                    _parsedAccountKey = OnePassword.AccountKey.Parse(AccountKey);

                return _parsedAccountKey;
            }
        }

        //
        // Private
        //

        private string _accountKey;
        private AccountKey _parsedAccountKey;
    }
}
