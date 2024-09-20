// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net.Http;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ClientTest : TestBase
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

            var e = Exceptions.AssertThrowsNetworkError(() => Client.Fetch(Username, Uki, rest), "A network error occurred");
            Assert.Equal(error, e.InnerException);
        }

        [Fact]
        private void Fetch_throws_on_invalid_username_or_password()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Incorrect authentification'}");
            Exceptions.AssertThrowsBadCredentials(() => Client.Fetch(Username, Uki, rest), "Invalid credentials");
        }

        [Fact]
        private void Fetch_throws_on_other_message()
        {
            var rest = new RestFlow().Post("{'objectType': 'message', 'content': 'Oops!'}");
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, Uki, rest), "Oops!");
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Uki = "uki";
        private const string FetchEndpoint = "/12/backup/latest";
    }
}
