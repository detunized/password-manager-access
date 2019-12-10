// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.OnePassword
{
    internal static class Extensions
    {
        //
        // string
        //

        // TODO: This is a tricky one. 1Password uses Decode64 in place of Decode64Loose.
        // Investigate and make sure the tests and the example work before removing it.
        //
        // Handles URL-safe, regular and mixed Base64 with or without padding.
        public static byte[] Decode64(this string s)
        {
            // Remove any padding.
            var withoutPadding = s.TrimEnd('=');

            // Re-pad correctly
            var withPadding = withoutPadding;
            switch (withoutPadding.Length % 4)
            {
            case 2:
                withPadding += "==";
                break;
            case 3:
                withPadding += "=";
                break;
            }

            // Convert to regular Base64
            var regularBase64 = withPadding.Replace('-', '+').Replace('_', '/');

            // Shouldn't fail anymore base of the padding or URL-safe.
            return Convert.FromBase64String(regularBase64);
        }

        //
        // byte[]
        //

        // TODO: This is a tricky one. 1Password uses Decode64 in place of Decode64Loose.
        // Investigate and make sure the tests and the example work before removing it.
        //
        // URL-safe Base64
        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        //
        // TODO: Switch to deserialization and remove this!
        //
        // Nested JToken access by path with and without exceptions
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new JTokenAccessException(
                        string.Format("Expected nested objects at '{0}'", path));

                c = c[i];
                if (c == null)
                    throw new JTokenAccessException(string.Format("Path '{0}' doesn't exist", path));
            }

            return c;
        }

        public static JToken At(this JToken j, string path, JToken defaultValue)
        {
            try
            {
                return j.At(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }

        public static string StringAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.String)
                throw new JTokenAccessException(string.Format("Expected a string at '{0}'", path));

            return (string)s;
        }

        public static string StringAt(this JToken j, string path, string defaultValue)
        {
            try
            {
                return j.StringAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }

        public static int IntAt(this JToken j, string path)
        {
            var i = j.At(path);
            if (i.Type != JTokenType.Integer)
                throw new JTokenAccessException(string.Format("Expected an integer at '{0}'", path));

            return (int)i;
        }

        public static int IntAt(this JToken j, string path, int defaultValue)
        {
            try
            {
                return j.IntAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }

        public static bool BoolAt(this JToken j, string path)
        {
            var b = j.At(path);
            if (b.Type != JTokenType.Boolean)
                throw new JTokenAccessException(string.Format("Expected a boolean at '{0}'", path));

            return (bool)b;
        }

        public static bool BoolAt(this JToken j, string path, bool defaultValue)
        {
            try
            {
                return j.BoolAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }
    }
}
