// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class ClientTest
    {
        [Fact]
        public void Login_returns_session()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.Unauthorized, headers: Step1Headers)
                .Post("", cookies: Step2Cookies);

            var session = Client.Login(TestData.Credentials, null, rest);

            Assert.Equal(SubAuth, session.Token);
            Assert.Equal(SubDeviceId, session.DeviceId);
        }

        [Fact]
        public void Logout_makes_POST_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Post("")
                    .ExpectUrl($"https://online.roboform.com/rf-api/{TestData.Username}?logout");

            Client.Logout(Session, rest.ToRestClient(BaseUrl));
        }

        [Fact]
        public void Logout_throws_on_not_HTTP_OK()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.NotFound);

            Exceptions.AssertThrowsInternalError(() => Client.Logout(Session, rest), "404");
        }

        [Fact]
        public void GetBlob_returns_received_bytes()
        {
            var expected = "All your base are belong to us";
            var rest = new RestFlow()
                .Get(expected);

            var blob = Client.GetBlob(Session, rest);

            Assert.Equal(expected.ToBytes(), blob);
        }

        [Fact]
        public void GetBlob_makes_GET_request_to_specific_url()
        {
            var rest = new RestFlow()
                .Get("")
                    .ExpectUrl($"https://online.roboform.com/rf-api/{TestData.Username}/user-data.rfo");

            Client.GetBlob(Session, rest.ToRestClient(BaseUrl));
        }

        [Fact]
        public void GetBlob_throws_on_not_HTTP_OK()
        {
            var rest = new RestFlow()
                            .Get("", HttpStatusCode.NotFound);

            Exceptions.AssertThrowsInternalError(() => Client.GetBlob(Session, rest), "404");
        }

        [Fact]
        public void Step1_makes_POST_request_to_specific_url_with_headers()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.Unauthorized, headers: Step1Headers)
                    .ExpectUrl($"https://online.roboform.com/rf-api/{TestData.Username}?login")
                    // TODO: Add support for partial header match
                    .ExpectHeader("Authorization", "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzc" +
                                                   "y5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"");

            Client.Step1(TestData.Credentials, new Client.OtpOptions(), rest.ToRestClient(BaseUrl));
        }

        [Fact]
        public void Step1_returns_WWW_Authenticate_header()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.Unauthorized, headers: Step1Headers);

            var header = Client.Step1(TestData.Credentials, new Client.OtpOptions(), rest);

            Assert.Equal(TestData.EncodedAuthInfoHeader, header);
        }

        [Fact]
        public void Step1_throws_on_missing_WWW_Authenticate_header()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.Unauthorized, headers: RestClient.NoHeaders);

            Exceptions.AssertThrowsInternalError(
                () => Client.Step1(TestData.Credentials, new Client.OtpOptions(), rest),
                "WWW-Authenticate header is not found in the response");
        }

        [Fact]
        public void Step2_makes_POST_request_to_specific_url_and_headers_set()
        {
            var rest = new RestFlow()
                .Post("", cookies: Step2Cookies)
                    .ExpectUrl($"https://online.roboform.com/rf-api/{TestData.Username}?login")
                    // TODO: Add support for partial header match
                    .ExpectHeader("Authorization", "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"Yz1iaXdzLHI9LURlSFJ" +
                                                   "yWmpDOERaXzBlOFJHc2lzZ00yLXRqZ2YtNjBtLS1GQmhMUTI2dGcscD1lWk5RUE9z" +
                                                   "OHFIRi9nSGVSWXEyekhmZ0gxNmdJS05xdGFPak5rUjlrRTRrPQ==\"");

            Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest.ToRestClient(BaseUrl));
        }

        [Fact]
        public void Step2_makes_POST_request_with_channel_set_to_dash_when_no_MFA_present()
        {
            var rest = new RestFlow()
                .Post("", cookies: Step2Cookies)
                    .ExpectHeader("x-sib-auth-alt-channel", "-");

            Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest);
        }

        [Fact]
        public void Step2_makes_POST_request_with_x_sib_headers_set_when_MFA_is_present()
        {
            var rest = new RestFlow()
                .Post("", cookies: Step2Cookies)
                    .ExpectHeader("x-sib-auth-alt-channel", "channel")
                    .ExpectHeader("x-sib-auth-alt-otp", "otp")
                    .ExpectHeader("x-sib-auth-alt-memorize", "1");

            Client.Step2(TestData.Credentials,
                         new Client.OtpOptions("channel", "otp", true),
                         TestData.AuthInfo,
                         rest);
        }

        [Fact]
        public void Step2_returns_cookies()
        {
            var rest = new RestFlow()
                .Post("", cookies: Step2Cookies);

            var result = Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest);

            AsserSessionsAretEqual(result.Session, Session);
        }

        [Fact]
        public void Step2_ignores_extra_cookies()
        {
            var extraCookies = new Dictionary<string, string> { ["blah"] = "blah-blah" };
            var rest = new RestFlow()
                .Post("", cookies: Step2Cookies.MergeCopy(extraCookies));

            var result = Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest);

            AsserSessionsAretEqual(result.Session, Session);
        }

        [Fact]
        public void Step2_throws_on_missing_cookies()
        {
            var rest = new RestFlow()
                .Post("", cookies: new Dictionary<string, string>());

            Exceptions.AssertThrowsInternalError(
                () => Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest),
                "cookie wasn't found in the response");
        }

        [Fact]
        public void Step2_throws_on_HTTP_unuthorized()
        {
            var rest = new RestFlow()
                .Post("", HttpStatusCode.Unauthorized);

            Exceptions.AssertThrowsBadCredentials(
                () => Client.Step2(TestData.Credentials, new Client.OtpOptions(), TestData.AuthInfo, rest),
                "Invalid username or password");
        }

        [Fact]
        public void GenerateNonce_returns_string_of_correct_length()
        {
            var nonce = Client.GenerateNonce();
            Assert.Equal(22, nonce.Length);
        }

        [Fact]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader(TestData.Credentials);

            Assert.Equal(expected, header);
        }

        [Fact]
        public void Step2AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"Yz1iaXdzLHI9LURlSFJy" +
                           "WmpDOERaXzBlOFJHc2lzZ00yLXRqZ2YtNjBtLS1GQmhMUTI2dGcscD1lWk5RUE9zOH" +
                           "FIRi9nSGVSWXEyekhmZ0gxNmdJS05xdGFPak5rUjlrRTRrPQ==\"";
            var header = Client.Step2AuthorizationHeader(TestData.Credentials, TestData.AuthInfo);

            Assert.Equal(expected, header);
        }

        //
        // Helpers
        //

        private static void AsserSessionsAretEqual(Session a, Session b)
        {
            Assert.Equal(b.Token, a.Token);
            Assert.Equal(b.DeviceId, a.DeviceId);
            Assert.Equal(b.Cookies, a.Cookies);
        }

        //
        // Data
        //

        private const string BaseUrl = "https://online.roboform.com/rf-api/" + TestData.Username;
        private const string SubAuth = "AQAUABAAdN_MjkCW";
        private const string SubDeviceId = "B972fc9818e7";

        private static readonly Session Session = new Session(SubAuth, SubDeviceId);

        private static readonly Dictionary<string, string> Step1Headers = new Dictionary<string, string>
        {
            ["WWW-Authenticate"] = TestData.EncodedAuthInfoHeader,
        };

        private static readonly Dictionary<string, string> Step2Cookies = new Dictionary<string, string>
        {
            ["sib-auth"] = SubAuth,
            ["sib-deviceid"] = SubDeviceId,
        };
    }
}
