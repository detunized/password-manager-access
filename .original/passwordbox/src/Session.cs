// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordBox
{
    class Session
    {
        public Session(string id)
        {
            Id = id;
        }

        public string Id { get; private set; }
    }
}
