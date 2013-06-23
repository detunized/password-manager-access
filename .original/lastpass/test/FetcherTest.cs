using System.Collections.Specialized;
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
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.Is<string>(s => s == "https://lastpass.com/login.php"),
                                           It.IsAny<NameValueCollection>()))
                .Returns(Encoding.UTF8.GetBytes(""))
                .Verifiable();

            new Fetcher("username", "password").Login(webClient.Object);

            webClient.Verify();
        }
    }
}
