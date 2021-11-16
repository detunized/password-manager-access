// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class ClientInfoBrowser
    {
        public readonly string Username;
        public readonly string Password;
        public readonly string DeviceId;

        public ClientInfoBrowser(string username, string password, string deviceId)
        {
            Username = username;
            Password = password;
            DeviceId = deviceId;
        }
    }

    public class ClientInfoCliApi
    {
        public readonly string ClientId;
        public readonly string ClientSecret;
        public readonly string Password;
        public readonly string DeviceId;

        public ClientInfoCliApi(string clientId, string clientSecret, string password, string deviceId)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
            Password = password;
            DeviceId = deviceId;
        }
    }
}
