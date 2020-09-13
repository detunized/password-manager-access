// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal static class Util
    {
        internal static byte[] ComposeMasterKey(string password)
        {
            return Crypto.Sha256(Crypto.Sha256(password));
        }

        internal static byte[] DeriveMasterKeyAes(byte[] compositeMasterKey, Dictionary<string, object> parameters)
        {
            InternalErrorException MakeError(string name) =>
                new InternalErrorException($"AES KDF parameter '{name}' not found or it is of incorrect type");

            if (!(parameters.GetOrDefault("S", null) is byte[] salt))
                throw MakeError("S");

            if (!(parameters.GetOrDefault("R", null) is ulong iterations))
                throw MakeError("R");

            using var aes = Aes.Create();
            if (aes is null)
                throw new InternalErrorException("Failed to create AES");

            aes.KeySize = 256;
            aes.Key = salt;
            aes.Mode = CipherMode.ECB;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            var derivedKey = compositeMasterKey.Sub(0, 32);

            // Derive
            for (ulong i = 0; i < iterations; i++)
            {
                encryptor.TransformBlock(derivedKey, 0, 16, derivedKey, 0);
                encryptor.TransformBlock(derivedKey, 16, 16, derivedKey, 16);
            }

            return Crypto.Sha256(derivedKey);
        }

        internal static (byte[] EncryptionKey, byte[] HmacKey) DeriveDatabaseKeys(byte[] masterKey, byte[] masterSeed)
        {
            var size = masterKey.Length + masterSeed.Length;

            var s = new OutputSpanStream(stackalloc byte[size + 1]);
            s.WriteBytes(masterSeed);
            s.WriteBytes(masterKey);
            s.WriteByte(1);

            return (Crypto.Sha256(s.Span.Slice(0, size)), Crypto.Sha512(s.Span));
        }

        internal static byte[] ComputeBlockHmacKey(byte[] hmacKey, ulong blockIndex)
        {
            if (hmacKey.Length != 64)
                throw new InternalErrorException("HMAC key must be 64 bytes long");

            var io = new OutputSpanStream(stackalloc byte[8 + 64]);
            io.WriteUInt64(blockIndex);
            io.WriteBytes(hmacKey);

            return Crypto.Sha512(io.Span);
        }
    }
}
