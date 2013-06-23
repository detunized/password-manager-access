using LastPass;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherTest
    {
        [Test]
        public void Fetch()
        {
            // TODO: Mock WebClient and pass and pass it to Fetcher
            //       Currently this test doesn't really test anything
            new Fetcher("lastpass.ruby@gmail.com", "&nT%*pMWJb*7s6u1").Login();
            new Fetcher("lastpass.ruby@gmail.com", "&nT%*pMWJb*7s6u1", 5000).Login();
        }
    }
}
