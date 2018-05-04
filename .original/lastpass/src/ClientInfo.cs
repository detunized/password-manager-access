// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    public class ClientInfo
    {
        public readonly Mode Mode; // TODO: Rename to platform
        public readonly string Id;
        public readonly string Description;
        public readonly bool TrustThisDevice;

        public ClientInfo(Mode mode, string id, string description, bool trustThisDevice)
        {
            Mode = mode;
            Id = id;
            Description = description;
            TrustThisDevice = trustThisDevice;
        }
    }
}
