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

        private const string AccountDownloadUrl = "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0";
        private static readonly Session Session = new Session(SessionId, IterationCount);

        //
        // Fetch tests
        //

        [Test]
        public void Fetch_sets_cookies()
        {
            var headers = new WebHeaderCollection();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers);

            Fetcher.Fetch(Session, webClient.Object);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)),
                            headers["Cookie"]);
        }

        [Test]
        public void Fetch_requests_accounts_from_correct_url()
        {
            var response = "VGVzdCBibG9i".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response);

            Fetcher.Fetch(Session, webClient.Object);

            webClient.Verify(x => x.DownloadData(It.Is<string>(a => a == AccountDownloadUrl)));
        }

        [Test]
        public void Fetch_returns_blob()
        {
            var response = "VGVzdCBibG9i".ToBytes();
            var expectedBlob = "Test blob".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response);

            var blob = Fetcher.Fetch(Session, webClient.Object);

            Assert.AreEqual(expectedBlob, blob.Bytes);
            Assert.AreEqual(IterationCount, blob.KeyIterationCount);
        }

        [Test]
        public void Fetch_throws_on_WebException()
        {
            var webException = new WebException();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Throws(webException);

            var e = Assert.Throws<FetchException>(() => Fetcher.Fetch(Session, webClient.Object));
            Assert.AreEqual(FetchException.FailureReason.WebException, e.Reason);
            Assert.AreEqual(WebExceptionMessage, e.Message);
            Assert.AreSame(webException, e.InnerException);
        }

        [Test]
        public void Fetch_throws_on_invalid_response()
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns("Invalid base64 string!".ToBytes());

            var e = Assert.Throws<FetchException>(() => Fetcher.Fetch(Session, webClient.Object));
            Assert.AreEqual(FetchException.FailureReason.InvalidResponse, e.Reason);
            Assert.AreEqual("Invalid base64 in response", e.Message);
        }
    }
}
