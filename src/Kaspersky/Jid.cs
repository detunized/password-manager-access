// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Kaspersky
{
    internal class Jid
    {
        public readonly string UserId;
        public readonly string Host;
        public readonly string Resource;

        public readonly string Node;
        public readonly string Bare;
        public readonly string Full;

        public Jid(string userId, string host, string resource)
        {
            UserId = userId;
            Host = host;
            Resource = resource;

            Node = $"{UserId}#{Client.DeviceKind}#{Client.ServiceId}";
            Bare = $"{Node}@{Host}";
            Full = $"{Bare}/{Resource}";
        }
    }
}
