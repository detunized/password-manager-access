// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class JsonTest
    {
        [Fact]
        public void TryParse_returns_true_on_success_and_returns_parser_result()
        {
            var success = Json.TryParse("{}", out var jo);

            Assert.True(success);
            Assert.NotNull(jo);
        }

        [Fact]
        public void TryParse_returns_false_on_failure_and_sets_result_to_null()
        {
            var notNull = new JObject();
            var success = Json.TryParse("~not-a-json~", out notNull);
            Assert.False(success);
            Assert.Null(notNull);
        }
    }
}
