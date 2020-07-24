// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common
{
    internal static class Os
    {
        public static uint UnixSeconds()
        {
            return (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        public static long UnixMilliseconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
    }
}
