// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    // This is a clean reimplementation of https://tools.ietf.org/html/rfc5869
    // No strangely licensed code has been used here even as a reference.
    internal static class Hkdf
    {
        // Keep the public API the same
        public static byte[] Sha256(byte[] ikm, byte[] salt, byte[] info, int byteCount)
        {
            return Generate(ikm, salt, info, byteCount, nameof(HMACSHA256));
        }

        public static byte[] Sha384(byte[] ikm, byte[] salt, byte[] info, int byteCount)
        {
            return Generate(ikm, salt, info, byteCount, nameof(HMACSHA384));
        }

        // Internal implementation using HMAC algorithm name
        internal static byte[] Generate(byte[] ikm, byte[] salt, byte[] info, int byteCount, string hmacAlgorithmName)
        {
            // TODO: Remove obsolete HMAC.Create
            using var saltHmac = HMAC.Create(hmacAlgorithmName);
            if (saltHmac == null)
                throw new CryptographicException($"Failed to create HMAC instance for algorithm '{hmacAlgorithmName}'");
            saltHmac.Key = salt;

            var prk = saltHmac.ComputeHash(ikm);

            // TODO: Remove obsolete HMAC.Create
            using var prkHmac = HMAC.Create(hmacAlgorithmName);
            if (prkHmac == null)
                throw new CryptographicException($"Failed to create HMAC instance for algorithm '{hmacAlgorithmName}'");
            prkHmac.Key = prk;

            var result = new byte[0];
            var current = new byte[0];
            var counter = new byte[1];

            var hashSize = prkHmac.HashSize / 8;
            if (hashSize == 0)
                throw new CryptographicException($"HMAC algorithm '{hmacAlgorithmName}' has a hash size of 0");

            while (result.Length < byteCount)
            {
                if (counter[0] == 255)
                    throw new CryptographicException("HKDF iteration limit reached (255 iterations)");

                ++counter[0];

                var hmacInput = new byte[current.Length + info.Length + counter.Length];
                Buffer.BlockCopy(current, 0, hmacInput, 0, current.Length);
                Buffer.BlockCopy(info, 0, hmacInput, current.Length, info.Length);
                Buffer.BlockCopy(counter, 0, hmacInput, current.Length + info.Length, counter.Length);

                current = prkHmac.ComputeHash(hmacInput);

                var previousResultLength = result.Length;
                Array.Resize(ref result, previousResultLength + current.Length);
                Buffer.BlockCopy(current, 0, result, previousResultLength, current.Length);
            }

            if (result.Length > byteCount)
            {
                var truncatedResult = new byte[byteCount];
                Buffer.BlockCopy(result, 0, truncatedResult, 0, byteCount);
                return truncatedResult;
            }

            return result;
        }
    }
}
