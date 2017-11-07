// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
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
            MakeStep1().Verify(x => x.Post(It.Is<string>(s => s.Contains(Username)),
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
            Assert.That(Client.Step1(Username, Nonce, http.Object), Is.EqualTo(Step1Header));
        }

        [Test]
        public void Step1_throws_on_missing_WWW_Authenticate_header()
        {
            var http = SetupStep1(null);
            Assert.That(() => Client.Step1(Username, Nonce, http.Object),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader(Username, Nonce);

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
            MakeStep2().Verify(x => x.Post(It.Is<string>(s => s.Contains(Username)),
                                           It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step2_makes_POST_request_with_authorization_header_set()
        {
            MakeStep2().Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(
                    d => d.ContainsKey("Authorization") &&
                         d["Authorization"].StartsWith("TODO: step2-auth-header"))));
        }

        [Test]
        public void Step2_returns_cookies()
        {
            var http = SetupStep2();
            Assert.That(Client.Step2(Username, Password, Nonce, AuthInfo, http.Object),
                        Is.EqualTo(Step2Cookie));
        }

        [Test]
        public void Step2_throws_on_missing_cookies()
        {
            var http = SetupStep2(null);
            Assert.That(() => Client.Step2(Username, Password, Nonce, AuthInfo, http.Object),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Step2AuthorizationHeader_returns_header()
        {
            var expected = "TODO: step2-auth-header";
            var header = Client.Step2AuthorizationHeader(Username, Password, Nonce, AuthInfo);

            Assert.That(header, Is.EqualTo(expected));
        }

        [Test]
        public void ParseAuthInfo_returns_AuthInfo()
        {
            var encoded = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"cj0tRGVIUnJaakM4RFpfM" +
                          "GU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRPWk9PalVq" +
                          "WENkYnc9PSxpPTQwOTY=\"";
            var info = Client.ParseAuthInfo(encoded);

            Assert.That(info.Sid, Is.EqualTo("6Ag93Y02vihucO9IQl1fbg"));
            Assert.That(info.Data, Is.EqualTo("r=-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg," +
                                              "s=A+Ft8UM674OZOOjUjXCdbw==,i=4096"));
            Assert.That(info.Nonce, Is.EqualTo("-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg"));
            Assert.That(info.Salt, Is.EqualTo("A+Ft8UM674OZOOjUjXCdbw==".Decode64()));
            Assert.That(info.IterationCount, Is.EqualTo(4096));
            Assert.That(info.IsMd5, Is.False);
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
            Client.Step1(Username, Nonce, http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep1(string header = Step1Header)
        {
            var http = SetupPost(HttpStatusCode.Unauthorized,
                                 new Dictionary<string, string> {{"WWW-Authenticate", header}});
            return http;
        }

        public static Mock<IHttpClient> MakeStep2()
        {
            var http = SetupStep2();
            Client.Step2(Username, Password, Nonce, AuthInfo, http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep2(string cookie = Step2Cookie)
        {
            var http = SetupPost(HttpStatusCode.OK,
                                 new Dictionary<string, string> {{"Set-Cookie", cookie}});
            return http;
        }

        // TODO: Could be removed
        private static Mock<IHttpClient> SetupPost(HttpStatusCode status)
        {
            return SetupPost(status, new Dictionary<string, string>());
        }

        private static Mock<IHttpClient> SetupPost(HttpStatusCode status,
                                                   Dictionary<string, string> headers)
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

        private const string Username = "lastpass.ruby@gmail.com";
        private const string Password = "password";
        private const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";
        private const string Step1Header = "WWW-Authenticate-step1";
        private const string Step2Cookie = "step2-cookie";

        private static readonly Client.AuthInfo AuthInfo =
            new Client.AuthInfo(sid: "sid",
                                data: "data",
                                nonce: "nonce",
                                salt: "salt".ToBytes(),
                                iterationCount: 1337,
                                isMd5: false);
    }
}
