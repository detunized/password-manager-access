// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.LastPass
{
    internal static class Model
    {
        public class DuoStatus
        {
            [JsonProperty("status")]
            public string Status { get; set; } = "";

            [JsonProperty("oneTimeToken")]
            public string OneTimeToken { get; set; } = "";
        }
    }
}
