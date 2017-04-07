// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;

namespace TrueKey
{
    static class Extensions
    {
        //
        // Case insensitive nested JObject access by path with and without exceptions
        //

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

        //
        // Case insensitive nested JToken access by path with and without exceptions
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new ArgumentException("Must be nested objects all the way down");

                c = ((JObject)c).GetValue(i, StringComparison.OrdinalIgnoreCase);
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

                c = ((JObject)c).GetValue(i, StringComparison.OrdinalIgnoreCase);
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
    }
}
