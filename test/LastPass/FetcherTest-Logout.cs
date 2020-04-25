// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Net;
using Moq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    partial class FetcherTest
    {
        private const string LogoutUrl = "https://lastpass.com/logout.php";

        //
        // Logout tests
        //

        [Test]
        public void Logout_failed_because_of_WebException()
        {
            var webClient = SetupLogout(new ResponseOrException(new WebException()));
            Assert.Throws<LogoutException>(() => Fetcher.Logout(Session, webClient.Object));
        }

        [Test]
        public void Logout_sets_session_id_cookie()
        {
            var headers = new WebHeaderCollection();
            SuccessfullyLogout(headers);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)), headers["Cookie"]);
        }

        public void Logout_makes_POST_request_to_correct_url()
        {
            var webClient = SuccessfullyLogout();
            webClient.Verify(x => x.UploadValues(It.Is<string>(a => a == LogoutUrl),
                                                 It.IsAny<NameValueCollection>()));
        }

        public void Logout_makes_POST_request_with_correct_parameters()
        {
            var expectedValues = new NameValueCollection
            {
                {"method", "cli"},
                {"noredirect", "1"}
            };

            var webClient = SuccessfullyLogout();
            webClient.Verify(x => x.UploadValues(It.IsAny<string>(),
                                                 It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))));
        }

        //
        // Helpers
        //

        private static Mock<IWebClient> SetupLogout(ResponseOrException responseOrException,
                                                    WebHeaderCollection headers = null)
        {
            var webClient = new Mock<IWebClient>();

            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers ?? new WebHeaderCollection());

            responseOrException.ReturnOrThrow(
                webClient.Setup(x => x.UploadValues(It.IsAny<string>(),
                                                    It.IsAny<NameValueCollection>())));

            return webClient;
        }

        private static Mock<IWebClient> SuccessfullyLogout(WebHeaderCollection headers = null)
        {
            var webClient = SetupLogout(new ResponseOrException(FetchResponse), headers);
            Fetcher.Logout(Session, webClient.Object);
            return webClient;
        }
    }
}
