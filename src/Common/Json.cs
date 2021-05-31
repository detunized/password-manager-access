// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Common
{
    internal static class Json
    {
        public static bool TryParse(string json, out JObject o)
        {
            try
            {
                o = JObject.Parse(json);
                return true;
            }
            catch (JsonException)
            {
                o = null;
                return false;
            }
        }
    }
}
