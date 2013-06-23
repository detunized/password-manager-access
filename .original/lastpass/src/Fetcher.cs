using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace LastPass
{
    public class Fetcher
    {
        public Fetcher(string username, string password, int iterationCount = 1)
        {
            this.username = username;
            this.password = password;
            this.iterationCount = iterationCount;
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
                        {"username", username},
                        {"hash", FetcherHelper.MakeHash(username, password, iterationCount)},
                        {"iterations", iterationCount.ToString()}
                    });

                Console.WriteLine("===\npost: {0} {1}\n===", Encoding.UTF8.GetString(r), web.ResponseHeaders);
            }
        }

        private readonly string username;
        private readonly string password;
        private int iterationCount;
    }
}