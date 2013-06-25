using System.Collections.Specialized;
using System.Linq;
using System.Text;
using Moq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherTest
    {
        private const string UnknownEmailMessage = "Unknown email address.";

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = UnknownEmailMessage)]
        public void Login_failed_because_of_invalid_email()
        {
            var url = "https://lastpass.com/login.php";
            var username = "username";
            var password = "password";
            var expectedValues = new NameValueCollection
                {
                    {"method", "mobile"},
                    {"web", "1"},
                    {"xml", "1"},
                    {"username", username},
                    {"hash", "e379d972c3eb59579abe3864d850b5f54911544adfa2daf9fb53c05d30cdc985"},
                    {"iterations", "1"}
                };
            var response = Encoding.UTF8.GetBytes(string.Format(
                "<response><error message=\"{0}\" cause=\"unknownemail\" /></response>",
                UnknownEmailMessage));

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))))
                .Returns(response)
                .Verifiable();

            new Fetcher(username, password).Login(webClient.Object);
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
