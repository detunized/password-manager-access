// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.Duo.Response
{
    public struct Envelope<T>
    {
        [JsonProperty("stat", Required = Required.Always)]
        public string Status;

        [JsonProperty("message")]
        public string Message;

        [JsonProperty("response")]
        public T Payload;
    }

    public class SubmitFactor
    {
        [JsonProperty("txid")]
        public string TransactionId;
    }
}
