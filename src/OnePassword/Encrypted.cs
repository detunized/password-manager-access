// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class Encrypted
    {
        public readonly string KeyId;
        public readonly string Scheme;
        public readonly string Container;
        public readonly byte[] Iv;
        public readonly byte[] Ciphertext;

        public static Encrypted Parse(JToken json)
        {
            return new Encrypted(keyId: json.StringAt("kid"),
                                 scheme: json.StringAt("enc"),
                                 container: json.StringAt("cty"),
                                 iv: json.StringAt("iv", "").Decode64(),
                                 ciphertext: json.StringAt("data").Decode64());
        }

        public Encrypted(string keyId, string scheme, string container, byte[] iv, byte[] ciphertext)
        {
            KeyId = keyId;
            Scheme = scheme;
            Container = container;
            Iv = iv;
            Ciphertext = ciphertext;
        }

        public Dictionary<string, object> ToDictionary()
        {
            return new Dictionary<string, object>
            {
                {"kid", KeyId},
                {"enc", Scheme},
                {"cty", Container},
                {"iv", Iv.ToBase64()},
                {"data", Ciphertext.ToBase64()},
            };
        }
    }
}
