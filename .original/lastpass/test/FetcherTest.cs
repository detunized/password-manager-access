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
        [Test]
        public void Login()
        {
            const string url = "https://lastpass.com/login.php";
            const string username = "username";
            const string password = "password";
            var expectedValues = new NameValueCollection
                {
                    {"method", "mobile"},
                    {"web", "1"},
                    {"xml", "1"},
                    {"username", username},
                    {"hash", "e379d972c3eb59579abe3864d850b5f54911544adfa2daf9fb53c05d30cdc985"},
                    {"iterations", "1"}
                };

            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == url),
                                           It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))))
                .Returns(Encoding.UTF8.GetBytes(""))
                .Verifiable();

            new Fetcher(username, password).Login(webClient.Object);

            webClient.Verify();
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
