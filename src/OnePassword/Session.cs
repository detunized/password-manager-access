// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
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

        public static Session Parse(JToken json)
        {
            return new Session(id: json.StringAt("sessionID"),
                               keyFormat: json.StringAt("accountKeyFormat"),
                               keyUuid: json.StringAt("accountKeyUuid"),
                               srpMethod: json.StringAt("userAuth/method"),
                               keyMethod: json.StringAt("userAuth/alg"),
                               iterations: json.IntAt("userAuth/iterations"),
                               salt: json.StringAt("userAuth/salt").Decode64Loose());
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
