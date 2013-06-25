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
        private const string InvalidPasswordMessage = "Invalid password!";

        private const string Url = "https://lastpass.com/login.php";
        private const string Username = "username";
        private const string Password = "password";
        private readonly NameValueCollection _expectedValues = new NameValueCollection
            {
                {"method", "mobile"},
                {"web", "1"},
                {"xml", "1"},
                {"username", Username},
                {"hash", "e379d972c3eb59579abe3864d850b5f54911544adfa2daf9fb53c05d30cdc985"},
                {"iterations", "1"}
            };

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = UnknownEmailMessage)]
        public void Login_failed_because_of_unknown_email()
        {
            var response = Encoding.UTF8.GetBytes(string.Format(
                "<response><error message=\"{0}\" cause=\"unknownemail\" /></response>",
                UnknownEmailMessage));

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, _expectedValues))))
                .Returns(response);

            new Fetcher(Username, Password).Login(webClient.Object);
        }

        [Test]
        [ExpectedException(typeof(LoginException), ExpectedMessage = InvalidPasswordMessage)]
        public void Login_failed_because_of_invalid_password()
        {
            var response = Encoding.UTF8.GetBytes(string.Format(
                "<response><error message=\"{0}\" cause=\"unknownpassword\" /></response>",
                InvalidPasswordMessage));

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == Url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, _expectedValues))))
                .Returns(response);

            new Fetcher(Username, Password).Login(webClient.Object);
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
