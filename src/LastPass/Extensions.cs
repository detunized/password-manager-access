// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    static class Extensions
    {
        public static string ToUtf8(this byte[] x)
        {
            return Common.Extensions.ToUtf8(x);
        }

        public static string ToHex(this byte[] x)
        {
            return Common.Extensions.ToHex(x);
        }

        public static byte[] ToBytes(this string s)
        {
            return Common.Extensions.ToBytes(s);
        }

        public static byte[] DecodeHex(this string s)
        {
            return Common.Extensions.DecodeHex(s);
        }

        public static byte[] Decode64(this string s)
        {
            return Common.Extensions.Decode64(s);
        }
    }
}
