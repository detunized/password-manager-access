// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Dashlane
{
    // TODO: Remove this!
    static class Extensions
    {
        //
        // byte[]
        //

        public static byte[] Sub(this byte[] array, int start, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "Length should be nonnegative");

            var bytesLeft = Math.Max(array.Length - start, 0);
            var actualLength = Math.Min(bytesLeft, length);
            var sub = new byte[actualLength];
            if (actualLength > 0)
                Array.Copy(array, start, sub, 0, actualLength);

            return sub;
        }

        //
        // JToken
        //

        public static string GetString(this JToken jtoken, string path)
        {
            var t = jtoken.SelectToken(path);
            return t != null && t.Type == JTokenType.String ? (string)t : null;
        }
    }
}
