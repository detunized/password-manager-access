// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace Dashlane.Test
{
    static class Extensions
    {
        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }
    }
}
