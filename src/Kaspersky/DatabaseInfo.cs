// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal readonly struct DatabaseInfo
    {
        public readonly int Version;
        public readonly int Iterations;
        public readonly byte[] Salt;

        public static DatabaseInfo Parse(byte[] blob)
        {
            if (blob.Length < 24)
                throw new InternalErrorException($"Blob is too short ({blob.Length})");

            return blob.Open(r =>
            {
                var version = r.ReadInt32();
                var iterations = r.ReadInt32();
                var salt = r.ReadBytes(16);

                return new DatabaseInfo(version, iterations, salt);
            });
        }

        internal DatabaseInfo(int version, int iterations, byte[] salt)
        {
            Version = version;
            Iterations = iterations;
            Salt = salt;
        }
    }
}
