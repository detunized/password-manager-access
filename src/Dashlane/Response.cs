// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Dashlane.Response
{
    internal class LoginType
    {
        [JsonProperty(PropertyName = "exists", Required = Required.Always)]
        public readonly string Exists;
    }
}
