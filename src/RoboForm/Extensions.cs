// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.RoboForm
{
    internal static class Extensions
    {
        public static string StringAt(this JToken j, string name, string defaultValue)
        {
            return At(j, name, JTokenType.String, defaultValue);
        }

        public static int IntAt(this JToken j, string name, int defaultValue)
        {
            return At(j, name, JTokenType.Integer, defaultValue);
        }

        public static bool BoolAt(this JToken j, string name, bool defaultValue)
        {
            return At(j, name, JTokenType.Boolean, defaultValue);
        }

        private static T At<T>(JToken j, string name, JTokenType type, T defaultValue)
        {
            if (j?.Type == JTokenType.Object)
                if (j[name] is var field && field?.Type == type)
                    return field.ToObject<T>();

            return defaultValue;
        }
    }
}
