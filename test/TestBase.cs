// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;

namespace PasswordManagerAccess.Test
{
    public class TestBase
    {
        public string GetFixture(string name, string extension = "json")
        {
            var type = GetType();
            var names = type.Assembly.GetManifestResourceNames();
            var fullName = $"{type.Namespace}.Fixtures.{name}.{extension}";
            using (Stream stream = type.Assembly.GetManifestResourceStream(fullName))
            using (StreamReader reader = new StreamReader(stream))
                return reader.ReadToEnd();
        }
    }
}
