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
            // Arrange
            var rest = new RestFlow().Post(GetFixture("empty-vault")).ExpectUrl(FetchEndpoint);

            // Act/Assert
            Client.Fetch(Username, AccessKeys, rest);
        }

        [Fact]
        private void Fetch_makes_post_request_with_correct_parameters()
        {
            // Arrange
            var rest = new RestFlow()
                .Post(GetFixture("empty-vault"))
                .ExpectContent("\"timestamp\":0", "\"needsKeys\":false", "\"teamAdminGroups\":false", "\"transactions\":[]");

            // Act/Assert
            Client.Fetch(Username, AccessKeys, rest);
        }

        [Fact]
        private void Fetch_signs_request_with_username_and_device_access_keys()
        {
            // Arrange
            var rest = new RestFlow()
                .Post(GetFixture("empty-vault"))
                .ExpectHeader("Authorization", "DL1-HMAC-SHA256 Login=username,", ",DeviceAccessKey=access-key,");

            // Act/Assert
            Client.Fetch(Username, AccessKeys, rest);
        }

        [Fact]
        private void Fetch_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var rest = new RestFlow().Post("{}", error);

            var e = Exceptions.AssertThrowsNetworkError(() => Client.Fetch(rest), "A network error occurred");
            Assert.Equal(error, e.InnerException);
        }

        [Theory]
        [InlineData("error-unknown-userdevice-key")]
        [InlineData("error-invalid-authentication")]
        private void Fetch_throws_BadCredentials_on_bad_access_keys(string fixture)
        {
            var rest = new RestFlow().Post(GetFixture(fixture));
            Exceptions.AssertThrowsBadCredentials(() => Client.Fetch(Username, AccessKeys, rest), "Invalid access codes");
        }

        [Fact]
        private void Fetch_throws_InternalError_on_other_message()
        {
            var rest = new RestFlow().Post(GetFixture("error-other-message"));
            Exceptions.AssertThrowsInternalError(() => Client.Fetch(Username, AccessKeys, rest), "Oops, something went wrong!");
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string FetchEndpoint = "/sync/GetLatestContent";
        private const string AccessKey = "access-key";
        private const string SecretKey = "secret-key";
        private const string ServerKey = "server-key";
        private static readonly Client.AccessKeys AccessKeys = new(AccessKey, SecretKey, ServerKey);
    }
}
