using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using Moq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherTest
    {
        private const string WebExceptionMessage = "WebException occured";
        private const string UnknownEmailMessage = "Unknown email address.";
        private const string InvalidPasswordMessage = "Invalid password!";
        private const string UnknownReasonMessage = "Unknown reason";
        private const string InvalidResponseMessage = "Invalid base64 in response";

        private const string Url = "https://lastpass.com/login.php";
        private const string Username = "username";
        private const string Password = "password";
        private const int InitialIterationCount = 1;
        private const int CorrectIterationCount = 5000;
        private const string SessionId = "53ru,Hb713QnEVM5zWZ16jMvxS0";

        private static readonly NameValueCollection SharedExpectedValues = new NameValueCollection
            {
                {"method", "mobile"},
                {"web", "1"},
                {"xml", "1"},
                {"username", Username}
            };

        private static readonly NameValueCollection ExpectedValues1 = new NameValueCollection(SharedExpectedValues)
            {
                {"hash", "e379d972c3eb59579abe3864d850b5f54911544adfa2daf9fb53c05d30cdc985"},
                {"iterations", string.Format("{0}", InitialIterationCount)}
            };

        private static readonly NameValueCollection ExpectedValues2 = new NameValueCollection(SharedExpectedValues)
            {
                {"hash", "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"},
                {"iterations", string.Format("{0}", CorrectIterationCount)}
            };

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = WebExceptionMessage)]
        public void Login_failed_because_of_WebException()
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Throws<WebException>();

            Fetcher.Login(Username, Password, webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = UnknownEmailMessage)]
        public void Login_failed_because_of_unknown_email()
        {
            var response = string.Format("<response><error message=\"{0}\" cause=\"unknownemail\" /></response>",
                                         UnknownEmailMessage).ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Returns(response);

            Fetcher.Login(Username, Password, webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = InvalidPasswordMessage)]
        public void Login_failed_because_of_invalid_password()
        {
            var response = string.Format("<response><error message=\"{0}\" cause=\"unknownpassword\" /></response>",
                                         InvalidPasswordMessage).ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Returns(response);

            Fetcher.Login(Username, Password, webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = UnknownReasonMessage)]
        public void Login_failed_for_unknown_reason_with_error_element()
        {
            var response = "<response><error /></response>".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Returns(response);

            Fetcher.Login(Username, Password, webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = UnknownReasonMessage)]
        public void Login_failed_for_unknown_reason_without_error_element()
        {
            var response = "<response />".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Returns(response);

            Fetcher.Login(Username, Password, webClient.Object);
        }

        [Test]
        public void Login_rerequests_with_given_iterations()
        {
            var response1 = string.Format("<response><error iterations=\"{0}\" /></response>",
                                          CorrectIterationCount).ToBytes();
            var response2 = string.Format("<ok sessionid=\"{0}\" />", SessionId).ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues1))))
                .Returns(response1);

            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, ExpectedValues2))))
                .Returns(response2);

            var session = Fetcher.Login(Username, Password, webClient.Object);
            Assert.AreEqual(SessionId, session.Id);
        }

        [Test]
        public void Fetch_sets_cookies()
        {
            var session = new Session(SessionId, CorrectIterationCount);
            var headers = new WebHeaderCollection();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers);

            Fetcher.Fetch(session, webClient.Object);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)), headers["Cookie"]);
        }

        [Test]
        public void Fetch_returns_blob()
        {
            var session = new Session(SessionId, CorrectIterationCount);
            var response = "VGVzdCBibG9i".ToBytes();
            var expectedBlob = "Test blob".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response)
                .Verifiable();

            var blob = Fetcher.Fetch(session, webClient.Object);

            webClient.Verify();
            Assert.AreEqual(expectedBlob, blob.Bytes);
            Assert.AreEqual(CorrectIterationCount, blob.KeyIterationCount);
        }

        [Test]
        [ExpectedException(typeof(FetchException), ExpectedMessage = WebExceptionMessage)]
        public void Fetch_throws_on_WebException()
        {
            var session = new Session(SessionId, CorrectIterationCount);

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Throws<WebException>();

            Fetcher.Fetch(session, webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(FetchException), ExpectedMessage = InvalidResponseMessage)]
        public void Fetch_throws_on_invalid_response()
        {
            var session = new Session(SessionId, CorrectIterationCount);

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns("Invalid base64 string!".ToBytes());

            Fetcher.Fetch(session, webClient.Object);
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
