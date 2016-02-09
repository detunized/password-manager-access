// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class RemoteTest
    {
        public const string Username = "username";
        public const string Uki = "uki";
        public const string DeviceName = "device";
        public const string Token = "token";
        public const string FetchUrl = "https://www.dashlane.com/12/backup/latest";
        public const string RegisterStep1Url = "https://www.dashlane.com/6/authentication/sendtoken";
        public const string RegisterStep2Url = "https://www.dashlane.com/6/authentication/registeruki";

        [Test]
        public void Fetch_returns_received_json()
        {
            var response = new JObject();
            response["what"] = "ever";

            Assert.That(
                Remote.Fetch(Username, Uki, SetupWebClient("{'what': 'ever'}").Object),
                Is.EqualTo(response));
        }

        [Test]
        public void Fetch_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient();

            Remote.Fetch(Username, Uki, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == FetchUrl), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Test]
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

        [Test]
        public void Fetch_throws_on_network_error()
        {
            Assert.That(
                () => Remote.Fetch(Username, Uki, SetupWebClient(new WebException()).Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.NetworkError)
                    .And.Message.EqualTo("Network error occurred")
                    .And.InnerException.InstanceOf<WebException>());
        }

        [Test]
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
                Assert.That(
                    () => Remote.Fetch(Username, Uki, SetupWebClient(i).Object),
                    Throws
                        .TypeOf<FetchException>()
                        .And.Property("Reason").EqualTo(FetchException.FailureReason.InvalidResponse)
                        .And.Message.EqualTo("Invalid JSON in response")
                        .And.InnerException.InstanceOf<JsonException>());
            }
        }

        [Test]
        public void Fetch_throws_on_error_with_message()
        {
            var response = "{'error': {'message': 'Oops!'}}";
            Assert.That(
                () => Remote.Fetch(Username, Uki, SetupWebClient(response).Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.UnknownError)
                    .And.Message.EqualTo("Oops!"));
        }

        [Test]
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
                Assert.That(
                    () => Remote.Fetch(Username, Uki, SetupWebClient(i).Object),
                    Throws
                        .TypeOf<FetchException>()
                        .And.Property("Reason").EqualTo(FetchException.FailureReason.UnknownError)
                        .And.Message.EqualTo("Unknown error"));
            }
        }

        [Test]
        public void Fetch_throws_on_invalid_username_or_password()
        {
            var response = "{'objectType': 'message', 'content': 'Incorrect authentification'}";
            Assert.That(
                () => Remote.Fetch(Username, Uki, SetupWebClient(response).Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.InvalidCredentials)
                    .And.Message.EqualTo("Invalid username or password"));
        }

        [Test]
        public void Fetch_throws_on_other_message()
        {
            var response = "{'objectType': 'message', 'content': 'Oops!'}";
            Assert.That(
                () => Remote.Fetch(Username, Uki, SetupWebClient(response).Object),
                Throws
                    .TypeOf<FetchException>()
                    .And.Property("Reason").EqualTo(FetchException.FailureReason.UnknownError)
                    .And.Message.EqualTo("Oops!"));
        }

        [Test]
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
                Assert.That(
                    () => Remote.Fetch(Username, Uki, SetupWebClient(i).Object),
                    Throws
                        .TypeOf<FetchException>()
                        .And.Property("Reason").EqualTo(FetchException.FailureReason.UnknownError)
                        .And.Message.EqualTo("Unknown error"));
            }
        }

        [Test]
        public void RegisterUkiStep1_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep1(Username, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == RegisterStep1Url), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Test]
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

        [Test]
        public void RegisterUkiStep1_throws_on_network_error()
        {
            Assert.That(
                () => Remote.RegisterUkiStep1(Username, SetupWebClient(new WebException()).Object),
                Throws
                    .TypeOf<RegisterException>()
                    .And.Property("Reason").EqualTo(RegisterException.FailureReason.NetworkError)
                    .And.Message.EqualTo("Network error occurred")
                    .And.InnerException.InstanceOf<WebException>());
        }

        [Test]
        public void RegisterUkiStep1_throws_on_invalid_response()
        {
            Assert.That(
                () => Remote.RegisterUkiStep1(Username, SetupWebClient("NOT A GREAT SUCCESS").Object),
                Throws
                    .TypeOf<RegisterException>()
                    .And.Property("Reason").EqualTo(RegisterException.FailureReason.InvalidResponse)
                    .And.Message.EqualTo("Register UKI failed"));
        }

        [Test]
        public void RegisterUkiStep2_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == RegisterStep2Url), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Test]
        public void RegisterUkiStep2_makes_post_request_with_correct_username_and_other_parameters()
        {
            var webClient = SetupWebClient("SUCCESS");

            Remote.RegisterUkiStep2(Username, DeviceName, Uki, Token, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p =>
                        p["login"] == Username &&
                        p["deviceName"] == DeviceName &&
                        p["uki"] == Uki &&
                        p["token"] == Token)),
                Times.Once);
        }

        [Test]
        public void RegisterUkiStep2_throws_on_network_error()
        {
            Assert.That(
                () => Remote.RegisterUkiStep2(
                    Username,
                    DeviceName,
                    Uki,
                    Token,
                    SetupWebClient(new WebException()).Object),
                Throws
                    .TypeOf<RegisterException>()
                    .And.Property("Reason").EqualTo(RegisterException.FailureReason.NetworkError)
                    .And.Message.EqualTo("Network error occurred")
                    .And.InnerException.InstanceOf<WebException>());
        }

        [Test]
        public void RegisterUkiStep2_throws_on_invalid_response()
        {
            Assert.That(
                () => Remote.RegisterUkiStep2(
                    Username,
                    DeviceName,
                    Uki,
                    Token,
                    SetupWebClient("NOT A GREAT SUCCESS").Object),
                Throws
                    .TypeOf<RegisterException>()
                    .And.Property("Reason").EqualTo(RegisterException.FailureReason.InvalidResponse)
                    .And.Message.EqualTo("Register UKI failed"));
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
