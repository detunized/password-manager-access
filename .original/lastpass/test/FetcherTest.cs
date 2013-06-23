using System.Collections.Specialized;
using System.Net;
using System.Text;
using NUnit.Framework;
using Moq;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherTest
    {
        class WebClient: IWebClient
        {
            public byte[] UploadValues(string address, NameValueCollection data)
            {
                throw new System.NotImplementedException();
            }

            public WebHeaderCollection ResponseHeaders { get; private set; }
        }

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
