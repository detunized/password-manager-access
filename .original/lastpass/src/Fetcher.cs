// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
                return Login(username, password, multifactorPassword, webClient);
        }

        public static Session Login(string username, string password, string multifactorPassword, IWebClient webClient)
        {
            // First we need to request PBKDF2 key interation count
            var keyIterationCount = RequestIterationCount(username, webClient);

            // Knowing the iterations count we can hash the password and log in
            var response = Login(username, password, multifactorPassword, keyIterationCount, webClient);

            // Parse the response
            var ok = response.XPathSelectElement("ok");
            if (ok != null)
            {
                var sessionId = ok.Attribute("sessionid");
                if (sessionId != null)
                {
                    return new Session(sessionId.Value, keyIterationCount);
                }
            }

            throw CreateLoginException(response.XPathSelectElement("response/error"));
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
                response = webClient.DownloadData("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android");
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

        private static int RequestIterationCount(string username, IWebClient webClient)
        {
            Func<Exception, Exception> invalidInt = (e) => new LoginException(LoginException.FailureReason.InvalidResponse,
                                                                              "Iteration count is invalid",
                                                                              e);

            try
            {
                // LastPass server is supposed to return paint text int, nothing fancy.
                return int.Parse(webClient.UploadValues("https://lastpass.com/iterations.php",
                                                        new NameValueCollection {{"email", username}}).ToUtf8());
            }
            catch (WebException e)
            {
                throw new LoginException(LoginException.FailureReason.WebException, "WebException occured", e);
            }
            catch (FormatException e)
            {
                throw invalidInt(e);
            }
            catch (OverflowException e)
            {
                throw invalidInt(e);
            }
        }

        private static XDocument Login(string username,
                                       string password,
                                       string multifactorPassword,
                                       int keyIterationCount,
                                       IWebClient webClient)
        {
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

                return XDocument.Parse(webClient.UploadValues("https://lastpass.com/login.php",
                                                              parameters).ToUtf8());
            }
            catch (WebException e)
            {
                throw new LoginException(LoginException.FailureReason.WebException,
                                         "WebException occured",
                                         e);
            }
            catch (XmlException e)
            {
                throw new LoginException(LoginException.FailureReason.InvalidResponse,
                                         "Invalid XML in response",
                                         e);
            }
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