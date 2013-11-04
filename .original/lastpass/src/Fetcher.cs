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

        // TODO: Split this function, it's grown too big
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
                    return Login(username, password, int.Parse(iterations.Value), multifactorPassword, webClient);
                }

                var cause = error.Attribute("cause");
                var message = error.Attribute("message");
                if (cause != null)
                {
                    var causeValue = cause.Value;
                    switch (causeValue)
                    {
                    case "unknownemail":
                        throw new LoginException(LoginException.FailureReason.LastPassInvalidUsername,
                                                 "Invalid username");
                    case "unknownpassword":
                        throw new LoginException(LoginException.FailureReason.LastPassInvalidPassword,
                                                 "Invalid password");
                    case "googleauthrequired":
                        throw new LoginException(LoginException.FailureReason.LastPassMissingGoogleAuthenticatorCode,
                                                 "Google Authenticator code is missing");
                    case "googleauthfailed":
                        throw new LoginException(LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                                 "Google Authenticator code is incorrect");
                    case "yubikeyrestricted":
                        throw new LoginException(LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                                 "Yubikey password is missing or incorrect");
                    case "outofbandrequired":
                        throw new LoginException(LoginException.FailureReason.LastPassOutOfBandAuthenticationRequired,
                                                 "Out of band authentication required");
                    case "multifactorresponsefailed":
                        throw new LoginException(LoginException.FailureReason.LastPassOutOfBandAuthenticationFailed,
                                                 "Out of band authentication failed");
                    default:
                        throw new LoginException(LoginException.FailureReason.LastPassOther,
                                                 message != null ? message.Value : causeValue);
                    }
                }

                if (message != null)
                {
                    throw new LoginException(LoginException.FailureReason.LastPassOther, message.Value);
                }
            }

            throw new LoginException(LoginException.FailureReason.LastPassUnknown, "Unknown reason");
        }
    }
}