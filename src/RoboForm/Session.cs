// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm
{
    internal class Session
    {
        public readonly string Token;
        public readonly string DeviceId;
        public readonly string Header;

        public Session(string token, string deviceId)
        {
            Token = token;
            DeviceId = deviceId;

            // Join the cookies together into one header. That's what the browsers do.
            Header = string.Format("sib-auth={0}; sib-deviceid={1}", token, deviceId);
        }
    }
}
