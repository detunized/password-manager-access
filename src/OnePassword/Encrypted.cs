// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword;

internal class Encrypted
{
    public readonly string KeyId;
    public readonly string Scheme;
    public readonly string Container;
    public readonly byte[] Iv;
    public readonly byte[] Ciphertext;

    public static Encrypted Parse(Response.Encrypted json)
    {
        return new Encrypted(
            keyId: json.KeyId,
            scheme: json.Scheme,
            container: json.Container,
            iv: json.Iv?.Decode64Loose(), // This is optional
            ciphertext: json.Ciphertext.Decode64Loose()
        );
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
            { "kid", KeyId },
            { "enc", Scheme },
            { "cty", Container },
            { "iv", Iv.ToUrlSafeBase64NoPadding() },
            { "data", Ciphertext.ToUrlSafeBase64NoPadding() },
        };
    }

    public Response.Encrypted ToModel()
    {
        return new()
        {
            KeyId = KeyId,
            Scheme = Scheme,
            Container = Container,
            Iv = Iv.ToUrlSafeBase64NoPadding(),
            Ciphertext = Ciphertext.ToUrlSafeBase64NoPadding(),
        };
    }
}
