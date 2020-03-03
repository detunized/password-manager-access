// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class ExtensionsTest
    {
        //
        // StringAt
        //

        [Fact]
        public void JToken_StringAt_returns_string()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': 'v2',
                'k3': 'v3'
            }");

            Assert.Equal("v1", j.StringAt("k1", ""));
            Assert.Equal("v2", j.StringAt("k2", ""));
            Assert.Equal("v3", j.StringAt("k3", ""));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_StringAt_returns_default_value_on_non_string(string value)
        {
            var j = JObject.Parse($"{{'key': {value}}}");

            Assert.Equal("yo", j.StringAt("key", "yo"));
        }

        [Fact]
        public void JToken_StringAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("{'key': 'value'}");

            Assert.Equal("yo", j.StringAt("not-a-key", "yo"));
        }

        [Fact]
        public void JToken_StringAt_returns_default_value_when_token_is_null()
        {
            Assert.Equal("yo", (null as JToken).StringAt("key", "yo"));
        }

        //
        // IntAt
        //

        [Fact]
        public void JToken_IntAt_returns_int()
        {
            var j = JObject.Parse(@"{
                'k1': 13,
                'k2': 17,
                'k3': 19
            }");

            Assert.Equal(13, j.IntAt("k1", 0));
            Assert.Equal(17, j.IntAt("k2", 0));
            Assert.Equal(19, j.IntAt("k3", 0));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("'10'")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_IntAt_returns_default_value_on_non_ints(string value)
        {
            var j = JObject.Parse($"{{'key': {value}}}");

            Assert.Equal(1337, j.IntAt("key", 1337));
        }

        [Fact]
        public void JToken_IntAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("{'key': 'value'}");

            Assert.Equal(1337, j.IntAt("not-a-key", 1337));
        }

        [Fact]
        public void JToken_IntAt_returns_default_value_when_token_is_null()
        {
            Assert.Equal(1337, (null as JToken).IntAt("key", 1337));
        }

        //
        // BoolAt
        //

        [Fact]
        public void JToken_BoolAt_returns_bools()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': false,
                'k3': true
            }");

            Assert.True(j.BoolAt("k1", false));
            Assert.False(j.BoolAt("k2", true));
            Assert.True(j.BoolAt("k3", false));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("'true'")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_BoolAt_returns_default_value_on_non_bools(string value)
        {
            var j = JObject.Parse($"{{'key': {value}}}");

            Assert.False(j.BoolAt("key", false));
            Assert.True(j.BoolAt("key", true));
        }

        [Fact]
        public void JToken_BoolAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("{'key': 'value'}");

            Assert.False(j.BoolAt("not-a-key", false));
            Assert.True(j.BoolAt("not-a-key", true));
        }

        [Fact]
        public void JToken_BoolAt_returns_default_value_when_token_is_null()
        {
            Assert.False((null as JToken).BoolAt("key", false));
            Assert.True((null as JToken).BoolAt("key", true));
        }

        //
        // Mixed
        //

        [Fact]
        public void JToken_At_functions_work_on_nested_objects()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 1337},
                'k3': {'k33': {'k333': false}},
            }");

            Assert.Equal("yo", j["not-a-key"].StringAt("key", "yo"));
            Assert.Equal(1337, j["k2"].IntAt("k22", 0));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("'string'")]
        [InlineData("[]")]
        public void JToken_At_functions_return_default_value_when_token_is_not_an_object(string json)
        {
            var j = JToken.Parse(json);

            Assert.Equal("yo", j.StringAt("key", "yo"));
            Assert.Equal(1337, j.IntAt("key", 1337));
            Assert.True(j.BoolAt("key", true));
        }
    }
}
