// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class AuthInfoTest
    {
        [Test]
        public void Properties_are_set()
        {
            var info = new AuthInfo("sid", "data", "nonce", "salt".ToBytes(), 1337, true);

            Assert.That(info.Sid, Is.EqualTo("sid"));
            Assert.That(info.Data, Is.EqualTo("data"));
            Assert.That(info.Nonce, Is.EqualTo("nonce"));
            Assert.That(info.Salt, Is.EqualTo("salt".ToBytes()));
            Assert.That(info.IterationCount, Is.EqualTo(1337));
            Assert.That(info.IsMd5, Is.EqualTo(true));
        }

        [Test]
        public void Parse_returns_AuthInfo()
        {
            var encoded = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"cj0tRGVIUnJaakM4RFpfM" +
                          "GU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRPWk9PalVq" +
                          "WENkYnc9PSxpPTQwOTY=\"";
            var info = AuthInfo.Parse(encoded);

            Assert.That(info.Sid, Is.EqualTo(TestData.AuthInfo.Sid));
            Assert.That(info.Data, Is.EqualTo(TestData.AuthInfo.Data));
            Assert.That(info.Nonce, Is.EqualTo(TestData.AuthInfo.Nonce));
            Assert.That(info.Salt, Is.EqualTo(TestData.AuthInfo.Salt));
            Assert.That(info.IterationCount, Is.EqualTo(TestData.AuthInfo.IterationCount));
            Assert.That(info.IsMd5, Is.EqualTo(TestData.AuthInfo.IsMd5));
        }

        [Test]
        public void ParseAuthInfo_throws_on_missing_parts()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth"));
        }

        [Test]
        public void ParseAuthInfo_throws_on_invalid_realm()
        {
            VerifyThrows(() => AuthInfo.Parse("Realm sid=\"\",data=\"\""));
        }

        [Test]
        public void ParseAuthInfo_throws_on_invalid_parameters_format()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth sid=,data="));
        }

        [Test]
        public void ParseAuthInfo_throws_on_missing_sid()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth data=\"\""));
        }

        [Test]
        public void ParseAuthInfo_throws_on_missing_data()
        {
            VerifyThrows(() => AuthInfo.Parse("SibAuth sid=\"\""));
        }

        [Test]
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

        [Test]
        public void ParseAuthInfo_sets_is_md5_flag()
        {
            var data = "r=nonce,s=c2FsdA==,i=1337,o=pwdMD5";
            var info = AuthInfo.Parse(string.Format("SibAuth sid=\"sid\",data=\"{0}\"",
                                                    data.ToBase64()));

            Assert.That(info.IsMd5, Is.True);
        }

        //
        // Helpers
        //
        private static void VerifyThrows(Action action)
        {
            Assert.That(new TestDelegate(action),
                        ExceptionsTest.ThrowsInvalidResponseWithMessage("Invalid auth info"));
        }
    }
}
