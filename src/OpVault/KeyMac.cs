// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OpVault
{
    // Represents a key and [H]MAC key pair. They always go together since all the encryption is
    // authenticated: every time something is encrypted a MAC/tag is added.
    internal class KeyMac
    {
        public readonly byte[] Key;
        public readonly byte[] MacKey;

        public KeyMac(byte[] buffer)
        {
            if (buffer.Length != 64)
                throw new InvalidOperationException("Buffer must be exactly 64 bytes long");

            Key = buffer.Sub(0, 32);
            MacKey = buffer.Sub(32, 32);
        }

        public KeyMac(string base64): this(base64.Decode64())
        {
        }
    }
}
