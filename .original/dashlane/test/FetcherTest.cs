// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using Moq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class FetcherTest
    {
        private const string Username = "username";
        private const string Uki = "uki";
        private const string FetchUrl = "https://www.dashlane.com/12/backup/latest";

        [Test]
        public void Fetch_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClient();

            Fetcher.Fetch(Username, Uki, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(It.Is<string>(s => s == FetchUrl), It.IsAny<NameValueCollection>()),
                Times.Once);
        }

        [Test]
        public void Fetch_makes_post_request_with_correct_username_and_uki()
        {
            var webClient = SetupWebClient();

            Fetcher.Fetch(Username, Uki, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(p => p["login"] == Username && p["uki"] == Uki)),
                Times.Once);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException), ExpectedMessage = "Oops!")]
        public void Fetch_throws_on_error_with_message()
        {
            Fetcher.Fetch(Username, Uki, SetupWebClient("{'error': {'message': 'Oops!'}}").Object);
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
                Assert.That(
                    () => Fetcher.Fetch(Username, Uki, SetupWebClient(i).Object),
                    Throws.TypeOf<InvalidOperationException>().With.Message.EqualTo("Unknown error"));
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException), ExpectedMessage = "Invalid username or password")]
        public void Fetch_throws_on_invalid_username_or_password()
        {
            Fetcher.Fetch(Username, Uki, SetupWebClient(
                "{'objectType': 'message', 'content': 'Incorrect authentification'}").Object);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException), ExpectedMessage = "Oops!")]
        public void Fetch_throws_on_other_message()
        {
            Fetcher.Fetch(Username, Uki, SetupWebClient("{'objectType': 'message', 'content': 'Oops!'}").Object);
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
                    () => Fetcher.Fetch(Username, Uki, SetupWebClient(i).Object),
                    Throws.TypeOf<InvalidOperationException>().With.Message.EqualTo("Unknown error"));
            }
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
    }
}
