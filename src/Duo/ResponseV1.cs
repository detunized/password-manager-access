// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Duo.ResponseV1
{
    public class Status
    {
        [JsonProperty("result")]
        public string Result;

        [JsonProperty("status")]
        public string Message;
    }

    public class FetchToken: Status
    {
        [JsonProperty("cookie")]
        public string Cookie;
    }

    public class Poll: Status
    {
        [JsonProperty("result_url")]
        public string Url;
    }
}
