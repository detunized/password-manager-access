// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    public interface ILogger
    {
        void Log(DateTime timestamp, string text);
    }
}
