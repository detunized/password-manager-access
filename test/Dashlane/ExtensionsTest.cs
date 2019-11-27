// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ExtensionsTest
    {
        [Fact]
        public void JToken_GetString_returns_string()
        {
            Action<string, string> check = (json, key) =>
                Assert.Equal("value", JToken.Parse(json).GetString(key));

            check("{'key': 'value'}", "key");
            check("{'key': {'kee': 'value'}}", "key.kee");
        }

        [Fact]
        public void JToken_GetString_returns_null()
        {
            Action<string, string> check = (json, key) => Assert.Null(JToken.Parse(json).GetString(key));

            check("0", "key");
            check("''", "key");
            check("[]", "key");
            check("{}", "key");
            check("{'key': 0}", "key");
            check("{'key': []}", "key");
            check("{'key': {}}", "key");
            check("{'key': 'value'}", "kee");
        }
    }
}
