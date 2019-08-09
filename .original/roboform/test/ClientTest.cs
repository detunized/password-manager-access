// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using Moq;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void Logout_makes_POST_request_to_specific_url()
        {
            var expected = string.Format("https://online.roboform.com/rf-api/{0}?logout",
                                         TestData.Username);

            Logout(HttpStatusCode.OK).Verify(x => x.Post(It.Is<string>(s => s == expected),
                                                         It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Logout_throws_on_not_HTTP_OK()
        {
            Assert.That(() => Logout(HttpStatusCode.NotFound),
                        ExceptionsTest.ThrowsNetworkErrorWithMessage("NotFound (404)"));
        }

        [Test]
        public void GetBlob_returns_received_bytes()
        {
            var expected = "Blah, blah, blah...".ToBytes();
            var http = SetupGet(HttpStatusCode.OK, expected);
            var response = Client.GetBlob(TestData.Username, Session, http.Object);

            Assert.That(response, Is.EqualTo(expected));
        }

        [Test]
        public void GetBlob_throws_on_not_HTTP_OK()
        {
            var http = SetupGet(HttpStatusCode.NotFound, new byte[0]);
            Assert.That(() => Client.GetBlob(TestData.Username, Session, http.Object),
                        ExceptionsTest.ThrowsNetworkErrorWithMessage("NotFound (404)"));
        }

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
            Assert.That(
                Client.Step1(TestData.Credentials, new Client.OtpOptions(), http.Object),
                Is.EqualTo(Step1Header));
        }

        [Test]
        public void Step1_throws_on_missing_WWW_Authenticate_header()
        {
            var http = SetupStep1(null);
            Assert.That(
                () => Client.Step1(TestData.Credentials, new Client.OtpOptions(), http.Object),
                ExceptionsTest.ThrowsInvalidResponseWithMessage("WWW-Authenticate header"));
        }

        [Test]
        public void GenerateNonce_returns_string_of_correct_length()
        {
            var nonce = Client.GenerateNonce();
            Assert.That(nonce.Length, Is.EqualTo(22));
        }

        [Test]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader(TestData.Credentials);

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
        public void Step2_makes_POST_request_with_channel_header_set_to_dash()
        {
            MakeStep2().Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(d => d.ContainsKey("x-sib-auth-alt-channel") &&
                                                       d["x-sib-auth-alt-channel"] == "-")));
        }

        [Test]
        public void Step2_makes_POST_request_with_x_sib_headers_set()
        {
            MakeStep2("channel", "otp", true).Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(d => d.ContainsKey("x-sib-auth-alt-channel") &&
                                                       d["x-sib-auth-alt-channel"] == "channel" &&
                                                       d.ContainsKey("x-sib-auth-alt-otp") &&
                                                       d["x-sib-auth-alt-otp"] == "otp" &&
                                                       d.ContainsKey("x-sib-auth-alt-memorize") &&
                                                       d["x-sib-auth-alt-memorize"] == "1")));
        }

        [Test]
        public void Step2_returns_cookies()
        {
            var http = SetupStep2();
            var result = Client.Step2(TestData.Credentials,
                                      new Client.OtpOptions(),
                                      TestData.AuthInfo,
                                      http.Object);

            AssertEqual(result.Session, Session);
        }

        [Test]
        public void Step2_ignores_extra_cookies()
        {
            var http = SetupStep2(Step2Cookies.Concat(new[] {"blah=blah-blah"}).ToArray());
            var result = Client.Step2(TestData.Credentials,
                                      new Client.OtpOptions(),
                                      TestData.AuthInfo,
                                      http.Object);

            AssertEqual(result.Session, Session);
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
                Assert.That(() => Client.Step2(TestData.Credentials,
                                               new Client.OtpOptions(),
                                               TestData.AuthInfo,
                                               http.Object),
                            ExceptionsTest.ThrowsInvalidResponseWithMessage("cookie"));
            }
        }

        [Test]
        public void Step2_throws_http_unauthorized()
        {
            var http = SetupStep2(HttpStatusCode.Unauthorized);
            Assert.That(() => Client.Step2(TestData.Credentials,
                                           new Client.OtpOptions(),
                                           TestData.AuthInfo,
                                           http.Object),
                        ExceptionsTest.ThrowsIncorrectCredentialsWithMessage("Username or password"));
        }

        [Test]
        public void Step2AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"Yz1iaXdzLHI9LURlSFJy" +
                           "WmpDOERaXzBlOFJHc2lzZ00yLXRqZ2YtNjBtLS1GQmhMUTI2dGcscD1lWk5RUE9zOH" +
                           "FIRi9nSGVSWXEyekhmZ0gxNmdJS05xdGFPak5rUjlrRTRrPQ==\"";
            var header = Client.Step2AuthorizationHeader(TestData.Credentials, TestData.AuthInfo);

            Assert.That(header, Is.EqualTo(expected));
        }

        //
        // Helpers
        //

        public static Mock<IHttpClient> Logout(HttpStatusCode status)
        {
            var http = SetupPost(status);
            Client.Logout(TestData.Username, Session, http.Object);
            return http;
        }

        public static Mock<IHttpClient> MakeStep1()
        {
            var http = SetupStep1();
            Client.Step1(TestData.Credentials, new Client.OtpOptions(), http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep1(string header = Step1Header)
        {
            var http = SetupPost(HttpStatusCode.Unauthorized,
                                 new KeyValuePair<string, string>("WWW-Authenticate", header));
            return http;
        }

        public static Mock<IHttpClient> MakeStep2(string otpChannel = null,
                                                  string otp = null,
                                                  bool rememberDevice = false)
        {
            var http = SetupStep2();
            Client.Step2(TestData.Credentials,
                         new Client.OtpOptions(otpChannel, otp, rememberDevice),
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

        public static Mock<IHttpClient> SetupStep2(HttpStatusCode status)
        {
            var http = SetupPost(status);
            return http;
        }

        private static Mock<IHttpClient> SetupGet(HttpStatusCode status, byte[] responseContent)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new ByteArrayContent(responseContent)
            };

            var http = new Mock<IHttpClient>();
            http
                .Setup(x => x.Get(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
                .Returns(response);

            return http;
        }

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

        private static void AssertEqual(Session a, Session b)
        {
            Assert.That(a.Token, Is.EqualTo(b.Token));
            Assert.That(a.DeviceId, Is.EqualTo(b.DeviceId));
            Assert.That(a.Header, Is.EqualTo(b.Header));
        }

        //
        // Data
        //

        private const string Step1Header = "WWW-Authenticate-step1";
        private static readonly string[] Step2Cookies =
        {
            // The cookies must be in the distant future, otherwise the tests stop working,
            // because the System.Net.CookieContainer ignores expired cookies.
            "sib-auth=AQAUABAAdN_MjkCW; path=/; expires=Wed, 07 Nov 2179 23:27:20 GMT; HttpOnly; Secure",
            "sib-deviceid=B972fc9818e7; path=/; expires=Wed, 07 Nov 2179 23:27:20 GMT; HttpOnly; Secure"
        };
        private static readonly Session Session = new Session("AQAUABAAdN_MjkCW", "B972fc9818e7");
    }
}
