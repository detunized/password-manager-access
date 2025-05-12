// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Hkdf
    {
        public static byte[] Sha1(byte[] ikm, byte[] salt, byte[] info, int byteCount) =>
            DeriveKey(ikm, salt, info, byteCount, HashAlgorithmName.SHA1);

        public static byte[] Sha256(byte[] ikm, byte[] salt, byte[] info, int byteCount) =>
            DeriveKey(ikm, salt, info, byteCount, HashAlgorithmName.SHA256);

        public static byte[] Sha384(byte[] ikm, byte[] salt, byte[] info, int byteCount) =>
            DeriveKey(ikm, salt, info, byteCount, HashAlgorithmName.SHA384);

        public static byte[] Sha512(byte[] ikm, byte[] salt, byte[] info, int byteCount) =>
            DeriveKey(ikm, salt, info, byteCount, HashAlgorithmName.SHA512);

        //
        // Internal
        //

        internal static byte[] DeriveKey(byte[] ikm, byte[] salt, byte[] info, int byteCount, HashAlgorithmName hash)
        {
            if (byteCount < 0)
                throw new InternalErrorException("Byte count should be nonnegative");

            return HKDF.DeriveKey(hash, ikm, byteCount, salt, info);
        }
    }
}
