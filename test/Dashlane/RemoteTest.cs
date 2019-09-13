// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class RemoteTest
    {
        public const string Username = "username";
        public const string Uki = "uki";
        public const string DeviceName = "device";
        public const string Token = "token";
        public const string LoginTypeUrl = "https://ws1.dashlane.com/7/authentication/exists";
        public const string FetchUrl = "https://ws1.dashlane.com/12/backup/latest";
        public const string RegisterStep1Url = "https://ws1.dashlane.com/6/authentication/sendtoken";
        public const string RegisterStep2Url = "https://ws1.dashlane.com/6/authentication/registeruki";

        //
        // RequestLoginType
        //

        [Fact]
        public void RequestLoginType_makes_post_request_to_specific_url()
        {
            var rest = new RestFlow().Post("{'exists': 'YES'}").ExpectUrl(LoginTypeUrl);
            Remote.RequestLoginType(Username, rest);
        }

        [Fact]
        public void RequestLoginType_requests_with_correct_username()
        {
            var rest = new RestFlow().Post("{'exists': 'YES'}").ExpectContent($"login={Username}");
            Remote.RequestLoginType(Username, rest);
        }

        [Theory]
        [InlineData("NO", Remote.LoginType.DoesntExist)]
        [InlineData("YES", Remote.LoginType.Regular)]
        [InlineData("YES_OTP_LOGIN", Remote.LoginType.GoogleAuth)]
        internal void RequestLoginType_returns_correct_login_type(string input, Remote.LoginType expected)
        {
            var rest = new RestFlow().Post($"{{'exists': '{input}'}}");
            Assert.Equal(expected, Remote.RequestLoginType(Username, rest));
        }

        [Fact]
        internal void RequestLoginType_throws_on_unknown_login_type()
        {
            var rest = new RestFlow().Post("{'exists': 'blah'}");
            Exceptions.AssertThrowsUnsupportedFeature(() => Remote.RequestLoginType(Username, rest),
                                                      "'blah' is not supported");
        }

        //
        // Fetch
        //

        [Fact]
        public void Fetch_returns_received_json()
        {
            var rest = new RestFlow().Post("{'what': 'ever'}");
            var response = new JObject();
            response["what"] = "ever";

            Assert.Equal(response, Remote.Fetch(Username, Uki, rest));
        }

        [Fact]
        public void Fetch_makes_post_request_to_specific_url()
        {
            var rest = new RestFlow().Post("{}").ExpectUrl(FetchUrl);
            Remote.Fetch(Username, Uki, rest);
        }

        [Fact]
        public void Fetch_makes_post_request_with_correct_username_and_uki()
        {
            var rest = new RestFlow().Post("{}").ExpectContent($"login={Username}", $"uki={Uki}");
            Remote.Fetch(Username, Uki, rest);
        }

        [Fact]
        public void Fetch_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("{}", error);

            var e = Exceptions.AssertThrowsNetworkError(() => Remote.Fetch(Username, Uki, rest),
                                                        "Network error occurred");
            Assert.Equal(error, e.InnerException);
        }

        [Fact]
        public void Fetch_throws_on_invalid_json_in_response()
        {
            string[] responses =
            {
                "",
                "0",
                "''",
                "[]",
                "} invalid {",
            };

            foreach (var i in responses)
            {
                var rest = new RestFlow().Post(i);
                var e = Exceptions.AssertThrowsInternalError(() => Remote.Fetch(Username, Uki, rest));

                Assert.Equal("Invalid JSON in response", e.Message);
                Assert.IsAssignableFrom<JsonException>(e.InnerException);
            }
        }

        [Fact]
        public void Fetch_throws_on_error_with_message()
        {
            var rest = new RestFlow().Post("{'error': {'message': 'Oops!'}}");
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, rest));

            Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
            Assert.Equal("Oops!", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void Fetch_throws_on_error_with_malformed_response()
        {
            string[] responses =
            {
                "{'error': null}",
                "{'error': {}}",
                "{'error': []}",
                "{'error': 0}",
                "{'error': ''}",

                "{'error': {'message': null}}",
                "{'error': {'message': {}}}",
                "{'error': {'message': []}}",
                "{'error': {'message': 0}}",
            };

            foreach (var i in responses)
            {
                var rest = new RestFlow().Post(i);
                var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, rest));

                Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
                Assert.Equal("Unknown error", e.Message);
                Assert.Null(e.InnerException);
            }
        }

        [Fact]
        public void Fetch_throws_on_invalid_username_or_password()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Incorrect authentification'}");
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, rest));

            Assert.Equal(FetchException.FailureReason.InvalidCredentials, e.Reason);
            Assert.Equal("Invalid username or password", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void Fetch_throws_on_other_message()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Oops!'}");
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, rest));

            Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
            Assert.Equal("Oops!", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void Fetch_throws_on_message_with_malformed_response()
        {
            string[] responses =
            {
                "{'objectType': 'message'}",
                "{'objectType': 'message', 'what': 'ever'}",
                "{'objectType': 'message', 'content': null}",
                "{'objectType': 'message', 'content': 0}",
                "{'objectType': 'message', 'content': []}",
                "{'objectType': 'message', 'content': {}}",
            };

            foreach (var i in responses)
            {
                var rest = new RestFlow().Post(i);
                var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, rest));

                Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
                Assert.Equal("Unknown error", e.Message);
                Assert.Null(e.InnerException);
            }
        }

        //
        // RegisterUkiStep1
        //

        [Fact]
        public void RegisterUkiStep1_makes_post_request_to_specific_url()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectUrl(RegisterStep1Url);
            Remote.RegisterUkiStep1(Username, rest);
        }

        [Fact]
        public void RegisterUkiStep1_makes_post_request_with_correct_username()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectContent($"login={Username}");
            Remote.RegisterUkiStep1(Username, rest);
        }

        [Fact]
        public void RegisterUkiStep1_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("", error);

            var e = Exceptions.AssertThrowsNetworkError(() => Remote.RegisterUkiStep1(Username, rest),
                                                        "Network error occurred");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        public void RegisterUkiStep1_throws_on_invalid_response()
        {
            var rest = new RestFlow().Post("NOT A GREAT SUCCESS");
            Exceptions.AssertThrowsInternalError(() => Remote.RegisterUkiStep1(Username, rest), "Register UKI failed");
        }

        //
        // RegisterUkiStep2
        //

        [Fact]
        public void RegisterUkiStep2_makes_post_request_to_specific_url()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectUrl(RegisterStep2Url);
            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, rest);
        }

        [Fact]
        public void RegisterUkiStep2_makes_post_request_with_correct_username_and_other_parameters()
        {
            var rest = new RestFlow()
                .Post("SUCCESS")
                .ExpectContent($"login={Username}", $"devicename={DeviceName}", $"uki={Uki}", $"token={Token}");
            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, rest);
        }

        [Fact]
        public void RegisterUkiStep2_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("", error);

            var e = Exceptions.AssertThrowsNetworkError(
                () => Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, rest),
                "Network error occurred");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        public void RegisterUkiStep2_throws_on_invalid_response()
        {
            var rest = new RestFlow().Post("NOT A GREAT SUCCESS");
            Exceptions.AssertThrowsInternalError(() => Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, rest),
                                                 "Register UKI failed");
        }
    }
}
