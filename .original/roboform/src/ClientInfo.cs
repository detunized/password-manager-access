// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm
{
    // TODO: This type is kinda useless. Used only in one function.
    //       Maybe store this in Client.Credentials instead of copying the fields.
    internal class ClientInfo
    {
        public readonly string Username;
        public readonly string Password;
        public readonly string DeviceId;

        public ClientInfo(string username, string password, string deviceId)
        {
            Username = username;
            Password = password;
            DeviceId = deviceId;
        }
    }
}
