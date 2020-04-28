// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    internal class Session
    {
        public readonly string Id;
        public readonly int KeyIterationCount;
        public readonly string Token;
        public readonly string EncryptedPrivateKey;
        public readonly Platform Platform;

        public Session(string id, int keyIterationCount, string token, string encryptedPrivateKey, Platform platform)
        {
            Id = id;
            KeyIterationCount = keyIterationCount;
            Token = token;
            EncryptedPrivateKey = encryptedPrivateKey;
            Platform = platform;
        }
    }
}
