// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.DropboxPasswords
{
    public class ClientInfo
    {
        public readonly string DeviceId;
        public readonly string DeviceName;

        public ClientInfo(string deviceId, string deviceName)
        {
            DeviceId = deviceId;
            DeviceName = deviceName;
        }
    }
}
