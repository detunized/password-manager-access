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
        private const string UnknownEmailMessage = "Unknown email address.";
        private const string InvalidPasswordMessage = "Invalid password!";
        private const string UnknownReasonMessage = "Unknown reason";

        private const string Url = "https://lastpass.com/login.php";
        private const string Username = "username";
        private const string Password = "password";
        private const int IterationCount1 = 1;
        private const int IterationCount2 = 5000;
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
                {"iterations", string.Format("{0}", IterationCount1)}
            };

        private static readonly NameValueCollection ExpectedValues2 = new NameValueCollection(SharedExpectedValues)
            {
                {"hash", "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"},
                {"iterations", string.Format("{0}", IterationCount2)}
            };

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

            new Fetcher(Username, Password).Login(webClient.Object);
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

            new Fetcher(Username, Password).Login(webClient.Object);
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

            new Fetcher(Username, Password).Login(webClient.Object);
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

            new Fetcher(Username, Password).Login(webClient.Object);
        }

        [Test]
        public void Login_rerequests_with_given_iterations()
        {
            var response1 = string.Format("<response><error iterations=\"{0}\" /></response>",
                                          IterationCount2).ToBytes();
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

            var session = new Fetcher(Username, Password).Login(webClient.Object);
            Assert.AreEqual(SessionId, session.Id);
        }

        [Test]
        public void Fetch_sets_cookies()
        {
            var session = new Fetcher.Session(SessionId);
            var headers = new WebHeaderCollection();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers);

            new Fetcher(Username, Password).Fetch(session, webClient.Object);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)), headers["Cookie"]);
        }

        [Test]
        public void Fetch_returns_blob()
        {
            var session = new Fetcher.Session(SessionId);
            var response = "VGVzdCBibG9i".ToBytes();
            var expectedBlob = "Test blob".ToBytes();
            var expectedEncryptionKey = "vtklQtp0DL5YesRbeQEgeheiVjaAss7aMEGVonM/FL4=".FromBase64();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response)
                .Verifiable();

            var blob = new Fetcher(Username, Password).Fetch(session, webClient.Object);

            webClient.Verify();
            Assert.AreEqual(expectedBlob, blob.Bytes);
            Assert.AreEqual(expectedEncryptionKey, blob.EncryptionKey);
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
