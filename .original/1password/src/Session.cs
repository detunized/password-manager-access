// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class Session
    {
        public readonly string Id;
        public readonly string KeyFormat;
        public readonly string KeyUuid;
        public readonly string SrpMethod;
        public readonly string KeyMethod;
        public readonly int Iterations;
        public readonly byte[] Salt;

        // TODO: Consider moving this out of here and just parse where we parse the response.
        //       JSON encoding is specific to a certain response and should be handled there.
        public static Session Parse(JToken json)
        {
            return new Session(id: json.StringAt("sessionID"),
                               keyFormat: json.StringAt("accountKeyFormat"),
                               keyUuid: json.StringAt("accountKeyUuid"),
                               srpMethod: json.StringAt("userAuth/method"),
                               keyMethod: json.StringAt("userAuth/alg"),
                               iterations: json.IntAt("userAuth/iterations"),
                               salt: json.StringAt("userAuth/salt").Decode64());
        }

        public Session(string id,
                       string keyFormat,
                       string keyUuid,
                       string srpMethod,
                       string keyMethod,
                       int iterations,
                       byte[] salt)
        {
            Id = id;
            KeyFormat = keyFormat;
            KeyUuid = keyUuid;
            SrpMethod = srpMethod;
            KeyMethod = keyMethod;
            Iterations = iterations;
            Salt = salt;
        }
    }
}
