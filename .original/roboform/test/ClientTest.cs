// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Moq;
using NUnit.Framework;
using System.Net.Http;

namespace RoboForm.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void Step1_makes_POST_request_to_specific_server()
        {
            MakeStep1().Verify(x => x.Post(
                It.Is<string>(s => s.StartsWith("https://online.roboform.com/")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step1_POST_request_url_contains_username()
        {
            MakeStep1().Verify(x => x.Post(It.Is<string>(s => s.Contains(TestData.Username)),
                                           It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step1_makes_POST_request_with_authorization_header_set()
        {
            MakeStep1().Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(
                    d => d.ContainsKey("Authorization") &&
                         d["Authorization"].StartsWith("SibAuth realm="))));
        }

        [Test]
        public void Step1_returns_WWW_Authenticate_header()
        {
            var http = SetupStep1();
            Assert.That(Client.Step1(TestData.Username, TestData.Nonce, http.Object),
                        Is.EqualTo(Step1Header));
        }

        [Test]
        public void Step1_throws_on_missing_WWW_Authenticate_header()
        {
            var http = SetupStep1(null);
            Assert.That(() => Client.Step1(TestData.Username, TestData.Nonce, http.Object),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader(TestData.Username, TestData.Nonce);

            Assert.That(header, Is.EqualTo(expected));
        }

        [Test]
        public void Step2_makes_POST_request_to_specific_server()
        {
            MakeStep2().Verify(x => x.Post(
                It.Is<string>(s => s.StartsWith("https://online.roboform.com/")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step2_POST_request_url_contains_username()
        {
            MakeStep2().Verify(x => x.Post(It.Is<string>(s => s.Contains(TestData.Username)),
                                           It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step2_makes_POST_request_with_authorization_header_set()
        {
            MakeStep2().Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(
                    d => d.ContainsKey("Authorization") &&
                         d["Authorization"].StartsWith("SibAuth sid="))));
        }

        [Test]
        public void Step2_returns_cookies()
        {
            var http = SetupStep2();
            Assert.That(Client.Step2(TestData.Username,
                                     TestData.Password,
                                     TestData.Nonce,
                                     TestData.AuthInfo,
                                     http.Object),
                        Is.EqualTo(Step2Header));
        }

        [Test]
        public void Step2_ignores_extra_cookies()
        {
            var http = SetupStep2(Step2Cookies.Concat(new[] {"blah=blah-blah"}).ToArray());
            Assert.That(Client.Step2(TestData.Username,
                                     TestData.Password,
                                     TestData.Nonce,
                                     TestData.AuthInfo,
                                     http.Object),
                        Is.EqualTo(Step2Header));
        }

        [Test]
        public void Step2_throws_on_missing_cookies()
        {
            var testCases = new[]
            {
                new string[] {},
                new[] {"sib-auth=auth"},
                new[] {"sib-deviceid=deviceid"},
                new[] {"blah=blah-blah"},
                new[] {"sib-auth=auth", "blah=blah-blah"},
            };

            foreach (var testCase in testCases)
            {
                var http = SetupStep2(testCase);
                Assert.That(() => Client.Step2(TestData.Username,
                                               TestData.Password,
                                               TestData.Nonce,
                                               TestData.AuthInfo,
                                               http.Object),
                            Throws.TypeOf<InvalidOperationException>());
            }
        }

        [Test]
        public void Step2AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"Yz1iaXdzLHI9LURlSFJy" +
                           "WmpDOERaXzBlOFJHc2lzZ00yLXRqZ2YtNjBtLS1GQmhMUTI2dGcscD1VdGQvV3FCSm" +
                           "5SU2pyeTBRTCswa3owUCtDUk5rcXRCYytySHVmRHllaUhrPQ==\"";
            var header = Client.Step2AuthorizationHeader(TestData.Username,
                                                         TestData.Password,
                                                         TestData.Nonce,
                                                         TestData.AuthInfo);

            Assert.That(header, Is.EqualTo(expected));
        }

        [Test]
        public void ParseAuthInfo_returns_AuthInfo()
        {
            var encoded = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"cj0tRGVIUnJaakM4RFpfM" +
                          "GU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRPWk9PalVq" +
                          "WENkYnc9PSxpPTQwOTY=\"";
            var info = Client.ParseAuthInfo(encoded);

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
            Assert.That(() => Client.ParseAuthInfo("SibAuth"),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void ParseAuthInfo_throws_on_invalid_realm()
        {
            Assert.That(() => Client.ParseAuthInfo("Realm sid=\"\",data=\"\""),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void ParseAuthInfo_throws_on_invalid_parameters_format()
        {
            Assert.That(() => Client.ParseAuthInfo("SibAuth sid=,data="),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void ParseAuthInfo_throws_on_missing_sid()
        {
            Assert.That(() => Client.ParseAuthInfo("SibAuth data=\"\""),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void ParseAuthInfo_throws_on_missing_data()
        {
            Assert.That(() => Client.ParseAuthInfo("SibAuth sid=\"\""),
                        Throws.TypeOf<InvalidOperationException>());
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
                Assert.That(
                    () => Client.ParseAuthInfo(string.Format("SibAuth sid=\"sid\",data=\"{0}\"",
                                                             data.ToBase64())),
                    Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void ParseAuthInfo_sets_is_md5_flag()
        {
            var data = "r=nonce,s=c2FsdA==,i=1337,o=pwdMD5";
            var info = Client.ParseAuthInfo(string.Format("SibAuth sid=\"sid\",data=\"{0}\"",
                                                          data.ToBase64()));

            Assert.That(info.IsMd5, Is.True);
        }

        //
        // Helpers
        //

        public static Mock<IHttpClient> MakeStep1()
        {
            var http = SetupStep1();
            Client.Step1(TestData.Username, TestData.Nonce, http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep1(string header = Step1Header)
        {
            var http = SetupPost(HttpStatusCode.Unauthorized,
                                 new KeyValuePair<string, string>("WWW-Authenticate", header));
            return http;
        }

        public static Mock<IHttpClient> MakeStep2()
        {
            var http = SetupStep2();
            Client.Step2(TestData.Username,
                         TestData.Password,
                         TestData.Nonce,
                         TestData.AuthInfo,
                         http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep2()
        {
            return SetupStep2(Step2Cookies);
        }

        public static Mock<IHttpClient> SetupStep2(string[] cookies)
        {
            var http = SetupPost(HttpStatusCode.OK,
                                 cookies
                                     .Select(i => new KeyValuePair<string, string>("Set-Cookie", i))
                                     .ToArray());
            return http;
        }

        // TODO: Could be removed
        private static Mock<IHttpClient> SetupPost(HttpStatusCode status)
        {
            return SetupPost(status, new KeyValuePair<string, string>[] {});
        }

        private static Mock<IHttpClient> SetupPost(HttpStatusCode status,
                                                   params KeyValuePair<string, string>[] headers)
        {
            var response = new HttpResponseMessage(status);
            foreach (var i in headers)
                response.Headers.Add(i.Key, i.Value);

            var http = new Mock<IHttpClient>();
            http
                .Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
                .Returns(response);

            return http;
        }

        //
        // Data
        //

        private const string Step1Header = "WWW-Authenticate-step1";
        private const string Step2Header = "sib-auth=AQAUABAAdN_MjkCW; sib-deviceid=B972fc9818e7";
        private static readonly string[] Step2Cookies =
        {
            "sib-auth=AQAUABAAdN_MjkCW; path=/; expires=Wed, 07 Nov 2018 23:27:20 GMT; HttpOnly; Secure",
            "sib-deviceid=B972fc9818e7; path=/; expires=Wed, 07 Nov 2018 23:27:20 GMT; HttpOnly; Secure"
        };
    }
}
