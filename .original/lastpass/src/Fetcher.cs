using System;
using System.Collections.Specialized;
using System.Net;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace LastPass
{
    static class Fetcher
    {
        public static Session Login(string username, string password, string multifactorPassword)
        {
            using (var webClient = new WebClient())
                return Login(username, password, 1, multifactorPassword, webClient);
        }

        public static Session Login(string username, string password, string multifactorPassword, IWebClient webClient)
        {
            return Login(username, password, 1, multifactorPassword, webClient);
        }

        public static Blob Fetch(Session session)
        {
            using (var webClient = new WebClient())
                return Fetch(session, webClient);
        }

        public static Blob Fetch(Session session, IWebClient webClient)
        {
            webClient.Headers.Add("Cookie", string.Format("PHPSESSID={0}", Uri.EscapeDataString(session.Id)));

            byte[] response;
            try
            {
                response = webClient.DownloadData("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0");
            }
            catch (WebException e)
            {
                throw new FetchException(FetchException.FailureReason.WebException, "WebException occured", e);
            }

            try
            {
                return new Blob(response.ToUtf8().Decode64(), session.KeyIterationCount);
            }
            catch (FormatException e)
            {
                throw new FetchException(FetchException.FailureReason.InvalidResponse, "Invalid base64 in response", e);
            }
        }

        private static Session Login(string username, string password, int keyIterationCount, string multifactorPassword, IWebClient webClient)
        {
            byte[] response;
            try
            {
                var parameters = new NameValueCollection
                    {
                        {"method", "mobile"},
                        {"web", "1"},
                        {"xml", "1"},
                        {"username", username},
                        {"hash", FetcherHelper.MakeHash(username, password, keyIterationCount)},
                        {"iterations", string.Format("{0}", keyIterationCount)}
                    };

                if (multifactorPassword != null)
                    parameters["otp"] = multifactorPassword;

                response = webClient.UploadValues("https://lastpass.com/login.php", parameters);
            }
            catch (WebException e)
            {
                throw new LoginException(LoginException.FailureReason.WebException, "WebException occured", e);
            }

            XDocument xml;
            try
            {
                xml = XDocument.Parse(response.ToUtf8());
            }
            catch (XmlException e)
            {
                throw new LoginException(LoginException.FailureReason.InvalidResponse, "Invalid XML in response", e);
            }

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
                    // TODO: Possible exception here in int.Parse
                    return Login(username, password, int.Parse(iterations.Value), multifactorPassword, webClient);
                }
            }

            throw CreateLoginException(error);
        }

        private static LoginException CreateLoginException(XElement error)
        {
            // XML is valid but there's nothing in it we can understand
            if (error == null)
            {
                return new LoginException(LoginException.FailureReason.UnknownResponseSchema, "Unknown response schema");
            }

            // Both of these are optional
            var cause = error.Attribute("cause");
            var message = error.Attribute("message");

            // We have a cause element, see if it's one of ones we know
            if (cause != null)
            {
                var causeValue = cause.Value;
                switch (causeValue)
                {
                case "unknownemail":
                    return new LoginException(LoginException.FailureReason.LastPassInvalidUsername,
                                              "Invalid username");
                case "unknownpassword":
                    return new LoginException(LoginException.FailureReason.LastPassInvalidPassword,
                                              "Invalid password");
                case "googleauthrequired":
                case "googleauthfailed":
                    return new LoginException(LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                              "Google Authenticator code is missing or incorrect");
                case "yubikeyrestricted":
                    return new LoginException(LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                              "Yubikey password is missing or incorrect");
                case "outofbandrequired":
                    return new LoginException(LoginException.FailureReason.LastPassOutOfBandAuthenticationRequired,
                                              "Out of band authentication required");
                case "multifactorresponsefailed":
                    return new LoginException(LoginException.FailureReason.LastPassOutOfBandAuthenticationFailed,
                                              "Out of band authentication failed");
                default:
                    return new LoginException(LoginException.FailureReason.LastPassOther,
                                              message != null ? message.Value : causeValue);
                }
            }

            // No cause, maybe at least a message
            if (message != null)
            {
                return new LoginException(LoginException.FailureReason.LastPassOther, message.Value);
            }

            // Nothing we know, just the error element
            return new LoginException(LoginException.FailureReason.LastPassUnknown, "Unknown reason");
        }
    }
}