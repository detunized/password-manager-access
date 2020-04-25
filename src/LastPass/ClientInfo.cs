// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    public class ClientInfo
    {
        public readonly Platform Platform;
        public readonly string Id;
        public readonly string Description;
        public readonly bool TrustThisDevice;

        public ClientInfo(Platform platform, string id, string description, bool trustThisDevice)
        {
            Platform = platform;
            Id = id;
            Description = description;
            TrustThisDevice = trustThisDevice;
        }
    }
}
