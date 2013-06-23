using System.Collections.Specialized;
using System.Globalization;

namespace LastPass
{
    public class Fetcher
    {
        public Fetcher(string username, string password, int iterationCount = 1)
        {
            _username = username;
            _password = password;
            _iterationCount = iterationCount;
        }

        public void Login()
        {
            using (var webClient = new WebClient())
            {
                Login(webClient);
            }
        }

        public void Login(IWebClient webClient)
        {
            webClient.UploadValues("https://lastpass.com/login.php", new NameValueCollection
                {
                    {"method", "mobile"},
                    {"web", "1"},
                    {"xml", "1"},
                    {"username", _username},
                    {"hash", FetcherHelper.MakeHash(_username, _password, _iterationCount)},
                    {"iterations", _iterationCount.ToString(CultureInfo.InvariantCulture)}
                });
        }

        private readonly string _username;
        private readonly string _password;
        private readonly int _iterationCount;
    }
}