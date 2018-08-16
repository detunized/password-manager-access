// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;

namespace OPVault
{
    internal static class Opdata01
    {
        public static byte[] Decrypt(string blobBase64, KeyMac key)
        {
            return Decrypt(blobBase64.Decode64(), key);
        }

        public static byte[] Decrypt(byte[] blob, KeyMac key)
        {
            if (blob.Length < 64)
                throw ParseError("too short");

            using (var io = new BinaryReader(new MemoryStream(blob)))
            {
                var magic = io.ReadBytes(8);
                if (!magic.SequenceEqual("opdata01".ToBytes()))
                    throw ParseError("invalid signature");

                // TODO: Sloppy! Assume 2G should be enough.
                // TODO: Should be little endian! This will not work on big endian platform!
                var length = (int)io.ReadInt64();
                var iv = io.ReadBytes(16);
                var padding = 16 - length % 16;

                if (blob.Length != 32 + padding + length + 32)
                    throw ParseError("invalid length");

                var ciphertext = io.ReadBytes(padding + length);
                var storedTag = io.ReadBytes(32);

                io.BaseStream.Seek(0, SeekOrigin.Begin);
                var hashedMessage = io.ReadBytes(32 + padding + length);

                var computedTag = Crypto.Hmac(hashedMessage, key);
                if (!computedTag.SequenceEqual(storedTag))
                    throw ParseError("tag doesn't match");

                var plaintext = Crypto.DecryptAes(ciphertext, iv, key);
                return plaintext.Skip(padding).Take(length).ToArray();
            }
        }

        private static Exception ParseError(string message)
        {
            // TODO: Use custom exception
            return new InvalidOperationException(string.Format("Opdata01 container is corrupted: {0}", message));
        }
    }
}
