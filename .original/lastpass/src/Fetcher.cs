using System;
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
            public Blob(byte[] bytes, byte[] encryptionKey)
            {
                Bytes = bytes;
                EncryptionKey = encryptionKey;
            }

            public byte[] Bytes { get; private set; }
            public byte[] EncryptionKey { get; private set; }
        }

        public Fetcher(string username, string password, int iterationCount = 1)
        {
            _username = username;
            _password = password;
            _iterationCount = iterationCount;
        }

        public Session Login()
        {
            using (var webClient = new WebClient())
            {
                return Login(webClient);
            }
        }

        public Session Login(IWebClient webClient)
        {
            // TODO: Handle web error and (possibly) rethrow them as LastPass errors
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
            webClient.Headers.Add("Cookie", string.Format("PHPSESSID={0}", Uri.EscapeDataString(session.Id)));

            // TODO: Handle web error and (possibly) rethrow them as LastPass errors
            var response = webClient.DownloadData("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0");

            return new Blob(response.ToUtf8().Decode64(),
                            FetcherHelper.MakeKey(_username, _password, _iterationCount));
        }

        private Session HandleLoginResponse(byte[] response, IWebClient webClient)
        {
            var xml = XDocument.Parse(response.ToUtf8());

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