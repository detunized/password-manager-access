// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test
{
    // Inherit this when fixtures are needed in the test
    public class TestBase
    {
        public static IEnumerable<object[]> ToMemberData<T>(params T[] e)
        {
            return e.Select(x => new object[] { x });
        }

        public static IEnumerable<TheoryDataRow<T>> ToTheoryData<T>(params T[] e)
        {
            return e.Select(x => new TheoryDataRow<T>(x));
        }

        public string GetFixture(string name, string extension = "json")
        {
            using var stream = GetFixtureStream(name, extension);
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        public byte[] GetBinaryFixture(string name, string extension)
        {
            using var stream = GetFixtureStream(name, extension);
            return stream.ReadAll();
        }

        public T ParseFixture<T>(string name)
        {
            return JsonConvert.DeserializeObject<T>(GetFixture(name, "json"));
        }

        //
        // Private
        //

        private Stream GetFixtureStream(string name, string extension)
        {
            var type = GetType();
            var fullName = $"{type.Namespace}.Fixtures.{name}.{extension}";
            return type.Assembly.GetManifestResourceStream(fullName);
        }
    }
}
