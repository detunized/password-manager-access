// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace RoboForm
{
    internal static class Extensions
    {
        //
        // string
        //

        public static string EncodeUri(this string s)
        {
            return Uri.EscapeUriString(s);
        }

        //
        // byte[]
        //

        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x);
        }
    }
}
