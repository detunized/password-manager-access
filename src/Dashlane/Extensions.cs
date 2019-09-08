// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Dashlane
{
    // TODO: Remove this!
    static class Extensions
    {
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
