// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace PasswordManagerAccess.Test
{
    // Inherit this when fixtures are needed in the test
    public class TestBase
    {
        public static IEnumerable<object[]> ToMemberData<T>(IEnumerable<T> e)
        {
            return e.Select(x => new object[] { x });
        }

        public string GetFixture(string name, string extension = "json")
        {
            var type = GetType();
            var names = type.Assembly.GetManifestResourceNames();
            var fullName = $"{type.Namespace}.Fixtures.{name}.{extension}";
            using (Stream stream = type.Assembly.GetManifestResourceStream(fullName))
            using (StreamReader reader = new StreamReader(stream))
                return reader.ReadToEnd();
        }

        public T ParseFixture<T>(string name)
        {
            return JsonConvert.DeserializeObject<T>(GetFixture(name, "json"));
        }
    }
}
