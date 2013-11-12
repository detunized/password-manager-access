// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    class Session
    {
        public Session(string id, int keyIterationCount)
        {
            Id = id;
            KeyIterationCount = keyIterationCount;
        }

        public string Id { get; private set; }
        public int KeyIterationCount { get; private set; }
    }
}