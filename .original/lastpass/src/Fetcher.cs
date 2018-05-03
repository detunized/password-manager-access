// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace LastPass
{
    static class Fetcher
    {
        public static Session Login(string username, string password, Mode mode, Ui ui)
        {
            using (var webClient = new WebClient())
                return Login(username, password, mode, ui, webClient);
        }

        // TODO: Write tests for this. Possibly the whole current concept of how it's tested
        //       should be rethought. Maybe should simply tests against a fake server.
        public static Session Login(string username, string password, Mode mode, Ui ui, IWebClient webClient)
        {
            // 1. First we need to request PBKDF2 key iteration count.
            var keyIterationCount = RequestIterationCount(username, webClient);

            // 2. Knowing the iterations count we can hash the password and log in.
            //    One the first attempt simply with the username and password.
            var response = PerformSingleLoginRequest(username,
                                                     password,
                                                     keyIterationCount,
                                                     new NameValueCollection(),
                                                     mode,
                                                     webClient);
            var session = ExtractSessionFromLoginResponse(response, keyIterationCount);
            if (session != null)
                return session;

            // 3. The simple login failed. This is usually due to some error, invalid credentials or
            //    a multifactor authentication being enabled.
            var cause = GetOptionalErrorAttribute(response, "cause");

            // 3.1. One-time-password is required
            if (KnownOtpMethods.ContainsKey(cause))
                return LoginWithOtp(username,
                                    password,
                                    keyIterationCount,
                                    KnownOtpMethods[cause],
                                    mode,
                                    ui,
                                    webClient);

            // 3.2. Some out-of-bound authentication is enabled. This does not require any
            //      additional input from the user.
            if (cause == "outofbandrequired")
                return LoginWithOob(username,
                                    password,
                                    keyIterationCount,
                                    ExtractOobMethodFromLoginResponse(response),
                                    mode,
                                    ui,
                                    webClient);

            throw CreateLoginException(response);
        }

        public static void Logout(Session session)
        {
            using (var webClient = new WebClient())
                Logout(session, webClient);
        }

        public static void Logout(Session session, IWebClient webClient)
        {
            try
            {
                SetSessionCookies(webClient, session);
                webClient.UploadValues("https://lastpass.com/logout.php",
                                       new NameValueCollection
                                       {
                                           {"method", "cli"},
                                           {"noredirect", "1"}
                                       });
            }
            catch (WebException e)
            {
                throw new LogoutException(LogoutException.FailureReason.WebException,
                                          "WebException occurred",
                                          e);
            }
        }

        public static Blob Fetch(Session session)
        {
            using (var webClient = new WebClient())
                return Fetch(session, webClient);
        }

        public static Blob Fetch(Session session, IWebClient webClient)
        {
            byte[] response;
            try
            {
                SetSessionCookies(webClient, session);
                response = webClient.DownloadData("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=cli");
            }
            catch (WebException e)
            {
                throw new FetchException(FetchException.FailureReason.WebException, "WebException occurred", e);
            }

            try
            {
                return new Blob(response.ToUtf8().Decode64(),
                                session.KeyIterationCount,
                                session.EncryptedPrivateKey);
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
                throw new LoginException(LoginException.FailureReason.WebException, "WebException occurred", e);
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

        private static XDocument PerformSingleLoginRequest(string username,
                                                           string password,
                                                           int keyIterationCount,
                                                           NameValueCollection extraParameters,
                                                           Mode mode,
                                                           IWebClient webClient)
        {
            try
            {
                var parameters = new NameValueCollection
                {
                    {"method", Modes[mode]},
                    {"xml", "2"},
                    {"username", username},
                    {"hash", FetcherHelper.MakeHash(username, password, keyIterationCount)},
                    {"iterations", string.Format("{0}", keyIterationCount)},
                    {"includeprivatekeyenc", "1"},
                    {"outofbandsupported", "1"},
                };
                parameters.Add(extraParameters);

                return XDocument.Parse(webClient.UploadValues("https://lastpass.com/login.php",
                                                              parameters).ToUtf8());
            }
            catch (WebException e)
            {
                throw new LoginException(LoginException.FailureReason.WebException,
                                         "WebException occurred",
                                         e);
            }
            catch (XmlException e)
            {
                throw new LoginException(LoginException.FailureReason.InvalidResponse,
                                         "Invalid XML in response",
                                         e);
            }
        }

        // Returns a valid session or throws
        private static Session LoginWithOtp(string username,
                                            string password,
                                            int keyIterationCount,
                                            Ui.SecondFactorMethod method,
                                            Mode mode,
                                            Ui ui,
                                            IWebClient webClient)
        {
            var otp = ui.ProvideSecondFactorPassword(method);
            var response = PerformSingleLoginRequest(username,
                                                     password,
                                                     keyIterationCount,
                                                     new NameValueCollection {{"otp", otp}},
                                                     mode,
                                                     webClient);
            var session = ExtractSessionFromLoginResponse(response, keyIterationCount);
            if (session != null)
                return session;

            throw CreateLoginException(response);
        }

        // Returns a valid session or throws
        private static Session LoginWithOob(string username,
                                            string password,
                                            int keyIterationCount,
                                            Ui.OutOfBandMethod method,
                                            Mode mode,
                                            Ui ui,
                                            IWebClient webClient)
        {
            var extraParameters = new NameValueCollection {{"outofbandrequest", "1"}};

            ui.AskToApproveOutOfBand(method);
            for (;;)
            {
                var response = PerformSingleLoginRequest(username,
                                                         password,
                                                         keyIterationCount,
                                                         extraParameters,
                                                         mode,
                                                         webClient);
                var session = ExtractSessionFromLoginResponse(response, keyIterationCount);
                if (session != null)
                    return session;

                if (GetOptionalErrorAttribute(response, "cause") != "outofbandrequired")
                    throw CreateLoginException(response);

                // Retry
                extraParameters["outofbandretry"] = "1";
                extraParameters["outofbandretryid"] = GetErrorAttribute(response, "retryid");
            }
        }

        private static string GetErrorAttribute(XDocument response, string name)
        {
            var attr = GetOptionalErrorAttribute(response, name);
            if (attr != null)
                return attr;

            throw new LoginException(LoginException.FailureReason.UnknownResponseSchema,
                                     string.Format("Unknown response schema, attribute {0} is missing", name));
        }

        private static string GetOptionalErrorAttribute(XDocument response, string name)
        {
            return response.XPathEvaluate(string.Format("string(response/error/@{0})", name)) as string;
        }

        private static Session ExtractSessionFromLoginResponse(XDocument response, int keyIterationCount)
        {
            var ok = response.XPathSelectElement("response/ok");
            if (ok == null)
                return null;

            var sessionId = ok.Attribute("sessionid");
            if (sessionId == null)
                return null;

            return new Session(sessionId.Value,
                               keyIterationCount,
                               GetEncryptedPrivateKey(ok));
        }

        private static Ui.OutOfBandMethod ExtractOobMethodFromLoginResponse(XDocument response)
        {
            var type = GetErrorAttribute(response, "outofbandtype");
            if (KnownOobMethods.ContainsKey(type))
                return KnownOobMethods[type];

            var name = GetOptionalErrorAttribute(response, "outofbandname");
            throw new LoginException(LoginException.FailureReason.UnsupportedFeature,
                                     string.Format("Out-of-band method '{0}' is not supported", name ?? type));
        }

        // Returned value could be missing or blank. In both of these cases we need null.
        private static string GetEncryptedPrivateKey(XElement ok)
        {
            var attr = ok.Attribute("privatekeyenc");
            if (attr == null)
                return null;

            var value = attr.Value;
            if (value.Length == 0)
                return null;

            return value;
        }

        private static LoginException CreateLoginException(XDocument response)
        {
            // XML is valid but there's nothing in it we can understand
            var error = response.XPathSelectElement("response/error");
            if (error == null)
                return new LoginException(LoginException.FailureReason.UnknownResponseSchema,
                                          "Unknown response schema");

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
                case "googleauthfailed":
                    return new LoginException(LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                              "Google Authenticator code is missing or incorrect");
                case "otpfailed":
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
                return new LoginException(LoginException.FailureReason.LastPassOther, message.Value);

            // Nothing we know, just the error element
            return new LoginException(LoginException.FailureReason.LastPassUnknown, "Unknown reason");
        }

        private static void SetSessionCookies(IWebClient webClient, Session session)
        {
            webClient.Headers.Add("Cookie", string.Format("PHPSESSID={0}", Uri.EscapeDataString(session.Id)));
        }

        private static readonly Dictionary<Mode, string> Modes = new Dictionary<Mode, string>
        {
            {Mode.Desktop, "cli"},
            {Mode.Mobile, "android"},
        };

        private static readonly Dictionary<string, Ui.SecondFactorMethod> KnownOtpMethods =
            new Dictionary<string, Ui.SecondFactorMethod>
            {
                {"googleauthrequired", Ui.SecondFactorMethod.GoogleAuth},
                {"otprequired", Ui.SecondFactorMethod.Yubikey},

            };

        private static readonly Dictionary<string, Ui.OutOfBandMethod> KnownOobMethods =
            new Dictionary<string, Ui.OutOfBandMethod>
            {
                {"lastpassauth", Ui.OutOfBandMethod.LastPassAuth},
                {"toopher", Ui.OutOfBandMethod.Toopher},
                {"duo", Ui.OutOfBandMethod.Duo},

            };
    }
}
