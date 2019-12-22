// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
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
                                 iv: json.StringAt("iv", "").Decode64Loose(),
                                 ciphertext: json.StringAt("data").Decode64Loose());
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
                {"iv", Iv.ToUrlSafeBase64NoPadding()},
                {"data", Ciphertext.ToUrlSafeBase64NoPadding()},
            };
        }
    }
}
