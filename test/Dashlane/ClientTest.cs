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
                                                  "Invalid UKI or email token");
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
        // Data
        //

        private const string Username = "username";
        private const string Uki = "uki";
        private const string FetchEndpoint = "/12/backup/latest";
    }
}
