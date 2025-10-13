// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal record Encrypted(string KeyId, string Scheme, string Container, byte[] Iv, byte[] Ciphertext)
    {
        public static Encrypted Parse(Response.Encrypted json)
        {
            return new Encrypted(
                KeyId: json.KeyId,
                Scheme: json.Scheme,
                Container: json.Container,
                Iv: json.Iv?.Decode64Loose(), // This is optional
                Ciphertext: json.Ciphertext.Decode64Loose()
            );
        }

        public Dictionary<string, object> ToDictionary()
        {
            return new Dictionary<string, object>(5)
            {
                ["kid"] = KeyId,
                ["enc"] = Scheme,
                ["cty"] = Container,
                ["iv"] = Iv.ToUrlSafeBase64NoPadding(),
                ["data"] = Ciphertext.ToUrlSafeBase64NoPadding(),
            };
        }

        public Response.Encrypted ToModel()
        {
            return new Response.Encrypted
            {
                KeyId = KeyId,
                Scheme = Scheme,
                Container = Container,
                Iv = Iv.ToUrlSafeBase64NoPadding(),
                Ciphertext = Ciphertext.ToUrlSafeBase64NoPadding(),
            };
        }
    }
}
