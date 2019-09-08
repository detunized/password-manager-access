// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
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
        public const string FetchUrl = "https://ws1.dashlane.com/12/backup/latest";
        public const string RegisterStep1Url = "https://ws1.dashlane.com/6/authentication/sendtoken";
        public const string RegisterStep2Url = "https://ws1.dashlane.com/6/authentication/registeruki";

        [Fact]
        public void Fetch_returns_received_json()
        {
            var response = new JObject();
            response["what"] = "ever";

            Assert.Equal(response, Remote.Fetch(Username, Uki, SetupWebClient("{'what': 'ever'}").Object));
        }

        [Fact]
        public void Fetch_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient();

            Remote.Fetch(Username, Uki, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == FetchUrl), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Fact]
        public void Fetch_makes_post_request_with_correct_username_and_uki()
        {
            var webClient = SetupWebClient();

            Remote.Fetch(Username, Uki, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p => p["login"] == Username && p["uki"] == Uki)),
                Times.Once);
        }

        [Fact]
        public void Fetch_throws_on_network_error()
        {
            var e = Assert.Throws<FetchException>(
                () => Remote.Fetch(Username, Uki, SetupWebClient(new WebException()).Object));

            Assert.Equal(FetchException.FailureReason.NetworkError, e.Reason);
            Assert.Equal("Network error occurred", e.Message);
            Assert.IsType<WebException>(e.InnerException);
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
                var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(i).Object));

                Assert.Equal(FetchException.FailureReason.InvalidResponse, e.Reason);
                Assert.Equal("Invalid JSON in response", e.Message);
                Assert.IsAssignableFrom<JsonException>(e.InnerException);
            }
        }

        [Fact]
        public void Fetch_throws_on_error_with_message()
        {
            var response = "{'error': {'message': 'Oops!'}}";
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(response).Object));

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
                var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(i).Object));

                Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
                Assert.Equal("Unknown error", e.Message);
                Assert.Null(e.InnerException);
            }
        }

        [Fact]
        public void Fetch_throws_on_invalid_username_or_password()
        {
            var response = "{'objectType': 'message', 'content': 'Incorrect authentification'}";
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(response).Object));

            Assert.Equal(FetchException.FailureReason.InvalidCredentials, e.Reason);
            Assert.Equal("Invalid username or password", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void Fetch_throws_on_other_message()
        {
            var response = "{'objectType': 'message', 'content': 'Oops!'}";
            var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(response).Object));

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
                var e = Assert.Throws<FetchException>(() => Remote.Fetch(Username, Uki, SetupWebClient(i).Object));

                Assert.Equal(FetchException.FailureReason.UnknownError, e.Reason);
                Assert.Equal("Unknown error", e.Message);
                Assert.Null(e.InnerException);
            }
        }

        [Fact]
        public void RegisterUkiStep1_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep1(Username, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == RegisterStep1Url), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Fact]
        public void RegisterUkiStep1_makes_post_request_with_correct_username()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep1(Username, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p => p["login"] == Username)),
                Times.Once);
        }

        [Fact]
        public void RegisterUkiStep1_throws_on_network_error()
        {
            var e = Assert.Throws<RegisterException>(
                () => Remote.RegisterUkiStep1(Username, SetupWebClient(new WebException()).Object));

            Assert.Equal(RegisterException.FailureReason.NetworkError, e.Reason);
            Assert.Equal("Network error occurred", e.Message);
            Assert.IsType<WebException>(e.InnerException);
        }

        [Fact]
        public void RegisterUkiStep1_throws_on_invalid_response()
        {
            var e = Assert.Throws<RegisterException>(
                () => Remote.RegisterUkiStep1(Username, SetupWebClient("NOT A GREAT SUCCESS").Object));

            Assert.Equal(RegisterException.FailureReason.InvalidResponse, e.Reason);
            Assert.Equal("Register UKI failed", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void RegisterUkiStep2_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == RegisterStep2Url), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Fact]
        public void RegisterUkiStep2_makes_post_request_with_correct_username_and_other_parameters()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p =>
                        p["login"] == Username &&
                        p["devicename"] == DeviceName &&
                        p["uki"] == Uki &&
                        p["token"] == Token)),
                Times.Once);
        }

        [Fact]
        public void RegisterUkiStep2_throws_on_network_error()
        {
            var e = Assert.Throws<RegisterException>(
                () => Remote.RegisterUkiStep2(
                    Username,
                    DeviceName,
                    Uki,
                    Token,
                    SetupWebClient(new WebException()).Object));

            Assert.Equal(RegisterException.FailureReason.NetworkError, e.Reason);
            Assert.Equal("Network error occurred", e.Message);
            Assert.IsType<WebException>(e.InnerException);
        }

        [Fact]
        public void RegisterUkiStep2_throws_on_invalid_response()
        {
            var e = Assert.Throws<RegisterException>(
                () => Remote.RegisterUkiStep2(
                    Username,
                    DeviceName,
                    Uki,
                    Token,
                    SetupWebClient("NOT A GREAT SUCCESS").Object));

            Assert.Equal(RegisterException.FailureReason.InvalidResponse, e.Reason);
            Assert.Equal("Register UKI failed", e.Message);
            Assert.Null(e.InnerException);
        }

        //
        // Helpers
        //

        private static Mock<IWebClient> SetupWebClient(string response = "{}")
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(response.ToBytes());

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClient(Exception e)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Throws(e);

            return webClient;
        }
    }
}
