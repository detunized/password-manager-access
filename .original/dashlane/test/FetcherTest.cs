// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        //
        // Helpers
        //

        private static Mock<IWebClient> SetupWebClient()
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(new byte[] {});

            return webClient;
        }
    }
}
