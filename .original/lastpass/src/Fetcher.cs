using System;
using System.Collections.Specialized;
using System.Globalization;
using System.Xml.Linq;
using System.Xml.XPath;

namespace LastPass
{
    public static class Fetcher
    {
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

        public static Session Login(string username, string password)
        {
            using (var webClient = new WebClient())
                return Fetcher.Login(username, password, 1, webClient);
        }

        public static Session Login(string username, string password, IWebClient webClient)
        {
            return Fetcher.Login(username, password, 1, webClient);
        }

        public static Blob Fetch(Session session)
        {
            using (var webClient = new WebClient())
                return Fetcher.Fetch(session, webClient);
        }

        public static Blob Fetch(Session session, IWebClient webClient)
        {
            webClient.Headers.Add("Cookie", string.Format("PHPSESSID={0}", Uri.EscapeDataString(session.Id)));

            // TODO: Handle web error and (possibly) rethrow them as LastPass errors
            var response = webClient.DownloadData("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0");

            // TODO: Remove hardcoded key, for testing only!
            return new Blob(response.ToUtf8().Decode64(),
                            "vtklQtp0DL5YesRbeQEgeheiVjaAss7aMEGVonM/FL4=".Decode64());
        }

        private static Session Login(string username, string password, int keyIterationCount, IWebClient webClient)
        {
            // TODO: Handle web error and (possibly) rethrow them as LastPass errors
            var response = webClient.UploadValues("https://lastpass.com/login.php", new NameValueCollection
                {
                    {"method", "mobile"},
                    {"web", "1"},
                    {"xml", "1"},
                    {"username", username},
                    {"hash", FetcherHelper.MakeHash(username, password, keyIterationCount)},
                    {"iterations", string.Format("{0}", keyIterationCount)}
                });

            return HandleLoginResponse(response, username, password, keyIterationCount, webClient);
        }

        private static Session HandleLoginResponse(byte[] response, string username, string password, int keyIterationCount, IWebClient webClient)
        {
            var xml = XDocument.Parse(response.ToUtf8());

            var ok = xml.Element("ok");
            if (ok != null)
            {
                var sessionId = ok.Attribute("sessionid");
                if (sessionId != null)
                {
                    return new Session(sessionId.Value, keyIterationCount);
                }
            }

            var error = xml.XPathSelectElement("response/error");
            if (error != null)
            {
                var iterations = error.Attribute("iterations");
                if (iterations != null)
                {
                    return Login(username, password, int.Parse(iterations.Value), webClient);
                }

                var message = error.Attribute("message");
                if (message != null)
                {
                    throw new LoginException(message.Value);
                }
            }

            throw new LoginException("Unknown reason");
        }
    }
}