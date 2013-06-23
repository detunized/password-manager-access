using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;

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
            using (var web = new WebClient())
            {
                var r = web.UploadValues("https://lastpass.com/login.php", new NameValueCollection()
                    {
                        {"method", "mobile"},
                        {"web", "1"},
                        {"xml", "1"},
                        {"username", _username},
                        {"hash", FetcherHelper.MakeHash(_username, _password, _iterationCount)},
                        {"iterations", _iterationCount.ToString()}
                    });

                Console.WriteLine("===\npost: {0} {1}\n===", Encoding.UTF8.GetString(r), web.ResponseHeaders);
            }
        }

        private readonly string _username;
        private readonly string _password;
        private readonly int _iterationCount;
    }
}