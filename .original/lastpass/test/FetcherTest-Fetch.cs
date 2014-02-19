// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Net;
using Moq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    partial class FetcherTest
    {
        //
        // Shared data
        //

        private const string AccountDownloadUrl = "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android";
        private static readonly Session Session = new Session(SessionId, IterationCount);
        private const string FetchResponse = "VGVzdCBibG9i";
        private static readonly byte[] Blob = "Test blob".ToBytes();

        //
        // Fetch tests
        //

        [Test]
        public void Fetch_sets_session_id_cookie()
        {
            var headers = new WebHeaderCollection();
            SuccessfullyFetch(headers);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)), headers["Cookie"]);
        }

        [Test]
        public void Fetch_requests_accounts_from_correct_url()
        {
            var webClient = SuccessfullyFetch();
            webClient.Verify(x => x.DownloadData(It.Is<string>(a => a == AccountDownloadUrl)));
        }

        [Test]
        public void Fetch_returns_blob()
        {
            Blob blob;
            SuccessfullyFetch(out blob);

            Assert.AreEqual(Blob, blob.Bytes);
            Assert.AreEqual(IterationCount, blob.KeyIterationCount);
        }

        [Test]
        public void Fetch_throws_on_WebException()
        {
            FetchAndVerifyException<WebException>(new ResponseOrException(new WebException()),
                                                  FetchException.FailureReason.WebException,
                                                  WebExceptionMessage);
        }

        [Test]
        public void Fetch_throws_on_invalid_response()
        {
            FetchAndVerifyException<FormatException>(new ResponseOrException("Invalid base64 string!"),
                                                     FetchException.FailureReason.InvalidResponse,
                                                     "Invalid base64 in response");
        }

        //
        // Helpers
        //

        private static Mock<IWebClient> SetupFetch(ResponseOrException responseOrException,
                                                   WebHeaderCollection headers = null)
        {
            var webClient = new Mock<IWebClient>();

            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers ?? new WebHeaderCollection());

            responseOrException.ReturnOrThrow(webClient.Setup(x => x.DownloadData(It.IsAny<string>())));

            return webClient;
        }

        private static Mock<IWebClient> SuccessfullyFetch(WebHeaderCollection headers = null)
        {
            Blob blob;
            return SuccessfullyFetch(out blob, headers);
        }

        private static Mock<IWebClient> SuccessfullyFetch(out Blob blob, WebHeaderCollection headers = null)
        {
            var webClient = SetupFetch(new ResponseOrException(FetchResponse), headers);
            blob = Fetcher.Fetch(Session, webClient.Object);
            return webClient;
        }

        private static void FetchAndVerifyException<TInnerExceptionType>(ResponseOrException responseOrException,
                                                                         FetchException.FailureReason reason,
                                                                         string message)
        {
            var webClient = SetupFetch(responseOrException);
            var exception = Assert.Throws<FetchException>(() => Fetcher.Fetch(Session, webClient.Object));

            Assert.AreEqual(reason, exception.Reason);
            Assert.AreEqual(message, exception.Message);
            Assert.IsInstanceOf<TInnerExceptionType>(exception.InnerException);
        }
    }
}
