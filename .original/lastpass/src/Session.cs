// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    class Session
    {
        public Session(string id, int keyIterationCount, string encryptedPrivateKey, Mode mode)
        {
            Id = id;
            KeyIterationCount = keyIterationCount;
            EncryptedPrivateKey = encryptedPrivateKey;
            Mode = mode;
        }

        public string Id { get; private set; }
        public int KeyIterationCount { get; private set; }
        public string EncryptedPrivateKey { get; private set; }
        public Mode Mode { get; private set; }
    }
}
