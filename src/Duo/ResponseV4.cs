// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Duo.ResponseV4
{
    public class Data
    {
        [JsonProperty("phones")]
        public Phone[] Phones;

        [JsonProperty("auth_method_order")]
        public Method[] Methods;
    }

    public class Phone
    {
        [JsonProperty("index")]
        public string Id;

        [JsonProperty("name")]
        public string Name;

        [JsonProperty("key")]
        public string Key;

        [JsonProperty("next_passcode")]
        public string NextPasscode;
    }

    public class Method
    {
        [JsonProperty("deviceKey")]
        public string DeviceKey;

        [JsonProperty("factor")]
        public string Factor;
    }

    public class Status
    {
        [JsonProperty("status_code")]
        public string Code;

        [JsonProperty("result")]
        public string Result;

        [JsonProperty("reason")]
        public string Reason;
    }
}
