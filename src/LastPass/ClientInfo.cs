// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    public class ClientInfo
    {
        public readonly Platform Platform;
        public readonly string Id;
        public readonly string Description;

        public ClientInfo(Platform platform, string id, string description)
        {
            Platform = platform;
            Id = id;
            Description = description;
        }
    }
}
