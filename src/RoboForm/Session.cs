// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace PasswordManagerAccess.RoboForm
{
    internal class Session
    {
        public readonly string Token;
        public readonly string DeviceId;
        public readonly Dictionary<string, string> Cookies;

        public Session(string token, string deviceId)
        {
            Token = token;
            DeviceId = deviceId;

            Cookies = new Dictionary<string, string>(2)
            {
                ["sib-auth"] = token,
                ["sib-deviceid"] = deviceId,
            };
        }
    }
}
