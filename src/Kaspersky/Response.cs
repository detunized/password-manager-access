// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Kaspersky.Response
{
    internal class Result
    {
        [JsonProperty("Status", Required = Required.Always)]
        public readonly string Status;
    }

    internal class Start: Result
    {
        [JsonProperty("LogonContext", Required = Required.Always)]
        public readonly string Context;
    }

    internal class UserToken
    {
        [JsonProperty("UserToken", Required = Required.Always)]
        public readonly string Token;

        [JsonProperty("TokenType", Required = Required.Always)]
        public readonly string Type;
    }

    internal class XmppSettings
    {
        [JsonProperty("userId", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty("pushNotificationEkaUniqueId", Required = Required.Always)]
        public readonly string PushNotificationEkaUniqueId;

        [JsonProperty("pushNotificationKpmServiceHasChangesUniqueId", Required = Required.Always)]
        public readonly string PushNotificationKpmServiceHasChangesUniqueId;

        [JsonProperty("commandResponseTimeout", Required = Required.Always)]
        public readonly int CommandResponseTimeout;

        [JsonProperty("commandLifetime", Required = Required.Always)]
        public readonly int CommandLifetime;

        [JsonProperty("xmppLibraryUrls", Required = Required.Always)]
        public readonly string[] XmppLibraryUrls;

        [JsonProperty("xmppCredentials", Required = Required.Always)]
        public readonly XmppCredentials XmppCredentials;
    }

    internal readonly struct XmppCredentials
    {
        [JsonProperty("userId", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty("password", Required = Required.Always)]
        public readonly string Password;
    }
}
