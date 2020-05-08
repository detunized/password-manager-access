// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    internal class Session
    {
        public readonly string Id;
        public readonly int KeyIterationCount;
        public readonly string Token;
        public readonly Platform Platform;
        public readonly string EncryptedPrivateKey;

        public Session(string id, int keyIterationCount, string token, Platform platform, string encryptedPrivateKey)
        {
            Id = id;
            KeyIterationCount = keyIterationCount;
            Token = token;
            Platform = platform;
            EncryptedPrivateKey = encryptedPrivateKey;
        }
    }
}
