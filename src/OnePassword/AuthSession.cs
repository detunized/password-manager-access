// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    internal class AuthSession
    {
        public readonly string KeyFormat;
        public readonly string KeyUuid;
        public readonly string SrpMethod;
        public readonly string KeyMethod;
        public readonly int Iterations;
        public readonly byte[] Salt;

        public AuthSession(string keyFormat,
                           string keyUuid,
                           string srpMethod,
                           string keyMethod,
                           int iterations,
                           byte[] salt)
        {
            KeyFormat = keyFormat;
            KeyUuid = keyUuid;
            SrpMethod = srpMethod;
            KeyMethod = keyMethod;
            Iterations = iterations;
            Salt = salt;
        }
    }
}
