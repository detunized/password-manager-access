// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;

namespace PasswordManagerAccess.Common
{
    // To be supplied by the user
    public interface ILogger
    {
        void Log(DateTime timestamp, string text);
    }

    // To be used internally by the library
    internal class Logger
    {
        public static Logger? WrapOrNull(ILogger? logger)
        {
            return logger == null ? null : new Logger(logger);
        }

        public Logger(ILogger logger)
        {
            _logger = logger;
        }

        public void Log(string text)
        {
            _logger.Log(DateTime.UtcNow, text);
        }

        public void Log(string format, params object[] args)
        {
            _logger.Log(DateTime.UtcNow, string.Format(format, args));
        }

        //
        // Private
        //

        private readonly ILogger _logger;
    }
}
