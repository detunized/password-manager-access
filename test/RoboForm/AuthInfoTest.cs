// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class AuthInfoTest
    {
        [Fact]
        public void Properties_are_set()
        {
            var info = new AuthInfo("sid", "data", "nonce", "salt".ToBytes(), 1337, true);

            Assert.Equal("sid", info.Sid);
            Assert.Equal("data", info.Data);
            Assert.Equal("nonce", info.Nonce);
            Assert.Equal("salt".ToBytes(), info.Salt);
            Assert.Equal(1337, info.IterationCount);
            Assert.True(info.IsMd5);
        }

        [Fact]
        public void Parse_returns_AuthInfo()
        {
            var encoded = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"cj0tRGVIUnJaakM4RFpfM" +
                          "GU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRPWk9PalVq" +
                          "WENkYnc9PSxpPTQwOTY=\"";
            var info = AuthInfo.Parse(encoded);

            Assert.Equal(TestData.AuthInfo.Sid, info.Sid);
            Assert.Equal(TestData.AuthInfo.Data, info.Data);
            Assert.Equal(TestData.AuthInfo.Nonce, info.Nonce);
            Assert.Equal(TestData.AuthInfo.Salt, info.Salt);
            Assert.Equal(TestData.AuthInfo.IterationCount, info.IterationCount);
            Assert.Equal(TestData.AuthInfo.IsMd5, info.IsMd5);
        }

        [Fact]
        public void ParseAuthInfo_throws_on_missing_parts()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth"));
        }

        [Fact]
        public void ParseAuthInfo_throws_on_invalid_realm()
        {
            VerifyThrows(() => AuthInfo.Parse("Realm sid=\"\",data=\"\""));
        }

        [Fact]
        public void ParseAuthInfo_throws_on_invalid_parameters_format()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth sid=,data="));
        }

        [Fact]
        public void ParseAuthInfo_throws_on_missing_sid()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth data=\"\""));
        }

        [Fact]
        public void ParseAuthInfo_throws_on_missing_data()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth sid=\"\""));
        }

        [Fact]
        public void ParseAuthInfo_throws_on_invalid_data()
        {
            var testCases = new[]
            {
                "",
                ",,,",
                "s=c2FsdA==,i=1337",
                "r=nonce,i=1337",
                "r=nonce,s=c2FsdA==",
            };

            foreach (var data in testCases)
                VerifyThrows(() => AuthInfo.Parse(string.Format("SibAuth sid=\"sid\",data=\"{0}\"",
                                                                data.ToBase64())));
        }

        [Fact]
        public void ParseAuthInfo_sets_is_md5_flag()
        {
            var data = "r=nonce,s=c2FsdA==,i=1337,o=pwdMD5";
            var info = AuthInfo.Parse(string.Format("SibAuth sid=\"sid\",data=\"{0}\"",
                                                    data.ToBase64()));

            Assert.True(info.IsMd5);
        }

        //
        // Helpers
        //
        private static void VerifyThrows(Action action)
        {
            var e = Assert.Throws<ClientException>(action);
            Assert.Equal(ClientException.FailureReason.InvalidResponse, e.Reason);
            Assert.Contains("Invalid auth info", e.Message);
        }
    }
}
