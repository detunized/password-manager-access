using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;

namespace LastPass
{
    public class Fetcher
    {
        public class Session
        {
            public Session(string id)
            {
                Id = id;
            }

            public string Id { get; private set; }
        }

        public class Blob
        {
        }

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

        public Session Login(IWebClient webClient)
        {
            var response = webClient.UploadValues("https://lastpass.com/login.php", new NameValueCollection
                {
                    {"method", "mobile"},
                    {"web", "1"},
                    {"xml", "1"},
                    {"username", _username},
                    {"hash", FetcherHelper.MakeHash(_username, _password, _iterationCount)},
                    {"iterations", _iterationCount.ToString(CultureInfo.InvariantCulture)}
                });

            return HandleLoginResponse(response, webClient);
        }

        public Blob Fetch(Session session)
        {
            using (var webClient = new WebClient())
            {
                return Fetch(session, webClient);
            }
        }

        public Blob Fetch(Session session, IWebClient webClient)
        {
            return new Blob();
        }

        private Session HandleLoginResponse(byte[] response, IWebClient webClient)
        {
            var xml = XDocument.Parse(Encoding.UTF8.GetString(response));

            var ok = xml.Element("ok");
            if (ok != null)
            {
                var sessionId = ok.Attribute("sessionid");
                if (sessionId != null)
                {
                    return new Session(sessionId.Value);
                }
            }

            var error = xml.XPathSelectElement("response/error");
            if (error != null)
            {
                var iterations = error.Attribute("iterations");
                if (iterations != null)
                {
                    _iterationCount = int.Parse(iterations.Value);
                    return Login(webClient);
                }

                var message = error.Attribute("message");
                if (message != null)
                {
                    throw new LoginException(message.Value);
                }
            }

            throw new LoginException("Unknown reason");
        }

        private readonly string _username;
        private readonly string _password;
        private int _iterationCount;
    }
}