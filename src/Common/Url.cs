// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common
{
    internal static class Url
    {
        // Returns null when not found
        internal static string ExtractQueryParameter(string url, string name)
        {
            var nameEquals = name + '=';
            var start = url.IndexOf(nameEquals, StringComparison.Ordinal);
            if (start < 0)
                return null;

            start += nameEquals.Length;
            var end = url.IndexOf('&', start);

            return end < 0
                ? url.Substring(start) // The last parameter
                : url.Substring(start, end - start);
        }
    }
}
