// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
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
            var info = AuthInfo.Parse(TestData.EncodedAuthInfoHeader);

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
            Exceptions.AssertThrowsInternalError(() => AuthInfo.Parse("SibAuth"),
                                                 "Invalid auth info format");
        }

        [Fact]
        public void ParseAuthInfo_throws_on_invalid_realm()
        {
            Exceptions.AssertThrowsInternalError(() => AuthInfo.Parse("Realm sid=\"\",data=\"\""),
                                                 "Invalid auth info realm");
        }

        [Fact]
        public void ParseAuthInfo_throws_on_invalid_parameters_format()
        {
            Exceptions.AssertThrowsInternalError(() => AuthInfo.Parse("SibAuth sid=,data="),
                                                 "Invalid auth info parameter format");
        }

        [Fact]
        public void ParseAuthInfo_throws_on_missing_sid()
        {
            Exceptions.AssertThrowsInternalError(() => AuthInfo.Parse("SibAuth data=\"\""),
                                                 "Invalid auth info");
        }

        [Fact]
        public void ParseAuthInfo_throws_on_missing_data()
        {
            Exceptions.AssertThrowsInternalError(() => AuthInfo.Parse("SibAuth sid=\"\""),
                                                 "Invalid auth info");
        }

        [Theory]
        [InlineData("")]
        [InlineData(",,,")]
        [InlineData("s=c2FsdA==,i=1337")]
        [InlineData("r=nonce,i=1337")]
        [InlineData("r=nonce,s=c2FsdA==")]
        public void ParseAuthInfo_throws_on_invalid_data(string data)
        {
            Exceptions.AssertThrowsInternalError(
                () => AuthInfo.Parse($"SibAuth sid=\"sid\",data=\"{data.ToBase64()}\""),
                "Invalid auth info");
        }

        [Fact]
        public void ParseAuthInfo_sets_is_md5_flag()
        {
            var data = "r=nonce,s=c2FsdA==,i=1337,o=pwdMD5".ToBase64();
            var info = AuthInfo.Parse($"SibAuth sid=\"sid\",data=\"{data}\"");

            Assert.True(info.IsMd5);
        }
    }
}
