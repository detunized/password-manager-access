// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net.Http;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ClientTest: TestBase
    {
        //
        // RequestLoginType
        //

        [Fact]
        private void RequestLoginType_makes_post_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Post("{'exists': 'YES'}").ExpectUrl(LoginTypeEndpoint);
            Client.RequestLoginType(Username, rest);
        }

        [Fact]
        private void RequestLoginType_requests_with_correct_username()
        {
            var rest = new RestFlow().Post("{'exists': 'YES'}").ExpectContent($"login={Username}");
            Client.RequestLoginType(Username, rest);
        }

        [Theory]
        [InlineData("NO", Client.LoginType.DoesntExist)]
        [InlineData("YES", Client.LoginType.Regular)]
        [InlineData("YES_OTP_NEWDEVICE", Client.LoginType.GoogleAuth_Once)]
        [InlineData("YES_OTP_LOGIN", Client.LoginType.GoogleAuth_Always)]
        internal void RequestLoginType_returns_correct_login_type(string input, Client.LoginType expected)
        {
            var rest = new RestFlow().Post($"{{'exists': '{input}'}}");
            Assert.Equal(expected, Client.RequestLoginType(Username, rest));
        }

        [Fact]
        internal void RequestLoginType_throws_on_unknown_login_type()
        {
            var rest = new RestFlow().Post("{'exists': 'blah'}");
            Exceptions.AssertThrowsUnsupportedFeature(() => Client.RequestLoginType(Username, rest),
                                                      "'blah' is not supported");
        }

        //
        // Fetch
        //

        [Fact]
        private void Fetch_makes_post_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Post(GetFixture("empty-vault")).ExpectUrl(FetchEndpoint);
            Client.Fetch(Username, Uki, rest);
        }

        [Fact]
        private void Fetch_makes_post_request_with_correct_username_uki_and_no_otp()
        {
            var rest = new RestFlow()
                .Post(GetFixture("empty-vault"))
                    .ExpectContent($"login={Username}", $"uki={Uki}")
                    .ExpectContent(s => Assert.DoesNotContain("otp=", s));
            Client.Fetch(Username, Uki, rest);
        }

        [Fact]
        private void Fetch_makes_post_request_with_correct_username_email_token_and_no_uki()
        {
            var rest = new RestFlow()
                .Post(GetFixture("empty-vault"))
                    .ExpectContent($"login={Username}", $"token={Otp}")
                    .ExpectContent(s => Assert.DoesNotContain("uki=", s));
            Client.Fetch(Username, Client.LoginType.Regular, Otp, rest);
        }

        [Theory]
        [InlineData(Client.LoginType.GoogleAuth_Once)]
        [InlineData(Client.LoginType.GoogleAuth_Always)]
        private void Fetch_makes_post_request_with_correct_username_otp_and_no_uki(Client.LoginType loginType)
        {
            var rest = new RestFlow()
                .Post(GetFixture("empty-vault"))
                    .ExpectContent($"login={Username}", $"otp={Otp}")
                    .ExpectContent(s => Assert.DoesNotContain("uki=", s));
            Client.Fetch(Username, loginType, Otp, rest);
        }

        [Fact]
        private void Fetch_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("{}", error);

            var e = Exceptions.AssertThrowsNetworkError(() => Client.Fetch(Username, Uki, rest),
                                                        "Network error occurred");
            Assert.Equal(error, e.InnerException);
        }

        [Theory]
        [InlineData("")]
        [InlineData("0")]
        [InlineData("''")]
        [InlineData("[]")]
        [InlineData("} invalid {")]
        private void Fetch_throws_on_invalid_json_in_response(string response)
        {
            var rest = new RestFlow().Post(response);
            var e = Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest));

            Assert.StartsWith("Invalid JSON in response", e.Message);
        }

        [Fact]
        private void Fetch_throws_on_error_with_message()
        {
            var rest = new RestFlow().Post("{'error': {'message': 'Oops!'}}");
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest), "Oops!");
        }

        [Theory]
        [InlineData("{'error': null}")]
        [InlineData("{'error': {}}")]
        [InlineData("{'error': []}")]
        [InlineData("{'error': 0}")]
        [InlineData("{'error': ''}")]
        [InlineData("{'error': {'message': null}}")]
        [InlineData("{'error': {'message': {}}}")]
        [InlineData("{'error': {'message': []}}")]
        [InlineData("{'error': {'message': 0}}")]
        private void Fetch_throws_on_error_with_malformed_response(string response)
        {
            var rest = new RestFlow().Post(response);
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest), "Unknown error");
        }

        [Fact]
        private void Fetch_throws_on_invalid_username_or_password()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Incorrect authentification'}");
            Exceptions.AssertThrowsBadMultiFactor(() => Client.Fetch(Username, Uki, rest),
                                                  "Invalid email token");
        }

        [Fact]
        private void Fetch_throws_on_other_message()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Oops!'}");
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest), "Oops!");
        }

        [Theory]
        [InlineData("{'objectType': 'message'}")]
        [InlineData("{'objectType': 'message', 'what': 'ever'}")]
        [InlineData("{'objectType': 'message', 'content': null}")]
        [InlineData("{'objectType': 'message', 'content': 0}")]
        [InlineData("{'objectType': 'message', 'content': []}")]
        [InlineData("{'objectType': 'message', 'content': {}}")]
        private void Fetch_throws_on_message_with_malformed_response(string response)
        {
            var rest = new RestFlow().Post(response);
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest), "Unknown error");
        }

        //
        // TriggerEmailWithToken
        //

        [Fact]
        private void TriggerEmailWithToken_makes_post_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectUrl(SendEmailEndpoint);
            Client.TriggerEmailWithPasscode(Username, rest);
        }

        [Fact]
        private void TriggerEmailWithToken_makes_post_request_with_correct_username()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectContent($"login={Username}");
            Client.TriggerEmailWithPasscode(Username, rest);
        }

        [Fact]
        private void TriggerEmailWithToken_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("", error);

            var e = Exceptions.AssertThrowsNetworkError(() => Client.TriggerEmailWithPasscode(Username, rest),
                                                        "network error occurred");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        private void TriggerEmailWithToken_throws_on_invalid_response()
        {
            var rest = new RestFlow().Post("NOT A GREAT SUCCESS");
            Exceptions.AssertThrowsInternalError(() => Client.TriggerEmailWithPasscode(Username, rest));
        }

        //
        // RegisterDeviceWithToken
        //

        [Fact]
        private void RegisterDeviceWithToken_makes_post_request_to_specific_endpoint()
        {
            var rest = new RestFlow().Post("SUCCESS").ExpectUrl(RegisterEndpoint);
            Client.RegisterDeviceWithToken(Username, Uki, DeviceName, Token, rest);
        }

        [Fact]
        private void RegisterDeviceWithToken_makes_post_request_with_correct_username_and_other_parameters()
        {
            var rest = new RestFlow()
                .Post("SUCCESS")
                .ExpectContent($"login={Username}", $"devicename={DeviceName}", $"uki={Uki}", $"token={Token}");
            Client.RegisterDeviceWithToken(Username, Uki, DeviceName, Token, rest);
        }

        [Fact]
        private void RegisterDeviceWithToken_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("", error);

            var e = Exceptions.AssertThrowsNetworkError(
                () => Client.RegisterDeviceWithToken(Username, Uki, DeviceName, Token, rest),
                "network error occurred");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        private void RegisterDeviceWithToken_throws_on_invalid_response()
        {
            var rest = new RestFlow().Post("NOT A GREAT SUCCESS");
            Exceptions.AssertThrowsInternalError(
                () => Client.RegisterDeviceWithToken(Username, Uki, DeviceName, Token, rest));
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Otp = "123456";
        private const string NoOtp = "";
        private const string Uki = "uki";
        private const string DeviceName = "device";
        private const string Token = "token";
        private const string LoginTypeEndpoint = "/7/authentication/exists";
        private const string FetchEndpoint = "/12/backup/latest";
        private const string SendEmailEndpoint = "/6/authentication/sendtoken";
        private const string RegisterEndpoint = "/6/authentication/registeruki";
    }
}
