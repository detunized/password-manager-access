// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.ZohoVault
{
    static class Extensions
    {
        //
        // JToken
        //

        // TODO: Refactor this to use type deserialization

        public static JToken At(this JObject j, string path)
        {
            return At(j.Root, path);
        }

        public static JToken AtOrNull(this JObject j, string path)
        {
            return AtOrNull(j.Root, path);
        }

        public static string StringAt(this JObject j, string path)
        {
            return StringAt(j.Root, path);
        }

        public static string StringAtOrNull(this JObject j, string path)
        {
            return StringAtOrNull(j.Root, path);
        }

        public static int IntAt(this JObject j, string path)
        {
            return IntAt(j.Root, path);
        }

        public static int? IntAtOrNull(this JObject j, string path)
        {
            return IntAtOrNull(j.Root, path);
        }

        //
        // JToken
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new ArgumentException("Must be nested objects all the way down");

                c = c[i];
                if (c == null)
                    throw new ArgumentException("Path doesn't exist", path);
            }

            return c;
        }

        public static JToken AtOrNull(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    return null;

                c = c[i];
                if (c == null)
                    return null;
            }

            return c;
        }

        public static string StringAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.String)
                throw new ArgumentException("The value is not a string");

            return (string)s;
        }

        public static string StringAtOrNull(this JToken j, string path)
        {
            var s = j.AtOrNull(path);
            if (s == null || s.Type != JTokenType.String)
                return null;

            return (string)s;
        }

        public static int IntAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.Integer)
                throw new ArgumentException("The value is not an integer");

            return (int)s;
        }

        public static int? IntAtOrNull(this JToken j, string path)
        {
            var s = j.AtOrNull(path);
            if (s == null || s.Type != JTokenType.Integer)
                return null;

            return (int)s;
        }
    }
}
