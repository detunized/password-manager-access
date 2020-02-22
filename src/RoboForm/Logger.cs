// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.RoboForm
{
    public abstract class Logger
    {
        public abstract void Log(DateTime timestamp, string text);

        public virtual void Log(DateTime timestamp, string format, params object[] args)
        {
            Log(timestamp, string.Format(format, args));
        }
    }
}
