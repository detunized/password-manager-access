// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string password,
                                          ClientInfo clientInfo,
                                          Ui ui,
                                          IRestTransport transport)
        {
            var rest = new RestClient(transport, "https://lastpass.com");
            var session = Login(username, password, clientInfo, ui, rest);
            try
            {
                var blob = Fetcher.Fetch(session);
                var key = blob.MakeEncryptionKey(username, password);
                return ParseVault(blob, key);
            }
            finally
            {
                Logout(session, rest);
            }
        }

        //
        // Internal
        //

        internal static Session Login(string username, string password, ClientInfo clientInfo, Ui ui, RestClient rest)
        {
            // 1. First we need to request PBKDF2 key iteration count.
            var keyIterationCount = RequestIterationCount(username, rest);

            // 2. Knowing the iterations count we can hash the password and log in.
            //    One the first attempt simply with the username and password.
            var response = PerformSingleLoginRequest(username,
                                                     password,
                                                     keyIterationCount,
                                                     new Dictionary<string, object>(),
                                                     clientInfo,
                                                     rest);
            var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
            if (session != null)
                return session;

            // 3. The simple login failed. This is usually due to some error, invalid credentials or
            //    a multifactor authentication being enabled.
            var cause = GetOptionalErrorAttribute(response, "cause");

            // 3.1. One-time-password is required
            if (KnownOtpMethods.TryGetValue(cause, out var otpMethod))
                session = LoginWithOtp(username,
                                       password,
                                       keyIterationCount,
                                       otpMethod,
                                       clientInfo,
                                       ui,
                                       rest);

            // 3.2. Some out-of-bound authentication is enabled. This does not require any
            //      additional input from the user.
            else if (cause == "outofbandrequired")
                session = LoginWithOob(username,
                                       password,
                                       keyIterationCount,
                                       ExtractOobMethodFromLoginResponse(response),
                                       clientInfo,
                                       ui,
                                       rest);

            // Nothing worked
            if (session == null)
                throw MakeLoginError(response);

            // 4. The login with OTP or OOB is successful. Tell the server to trust this device next time.
            if (clientInfo.TrustThisDevice)
                MarkDeviceAsTrusted(session, clientInfo, rest);

            return session;
        }

        internal static int RequestIterationCount(string username, RestClient rest)
        {
            var response = rest.PostForm("iterations.php", new Dictionary<string, object> {["email"] = username});
            if (!response.IsSuccessful)
                throw MakeError(response);

            // LastPass server is supposed to return plain text int, nothing fancy.
            if (int.TryParse(response.Content, out var count))
                return count;

            throw new InternalErrorException("Request iteration count failed: unexpected response");
        }

        internal static XDocument PerformSingleLoginRequest(string username,
                                                            string password,
                                                            int keyIterationCount,
                                                            Dictionary<string, object> extraParameters,
                                                            ClientInfo clientInfo,
                                                            RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                ["method"] = PlatformToUserAgent[clientInfo.Platform],
                ["xml"] = "2",
                ["username"] = username,
                ["hash"] = FetcherHelper.MakeHash(username, password, keyIterationCount),
                ["iterations"] = keyIterationCount,
                ["includeprivatekeyenc"] = "1",
                ["outofbandsupported"] = "1",
                ["uuid"] = clientInfo.Id,
            };

            if (clientInfo.TrustThisDevice)
                parameters["trustlabel"] = clientInfo.Description;

            foreach (var kv in extraParameters)
                parameters[kv.Key] = kv.Value;

            var response = rest.PostForm("login.php", parameters);
            if (response.IsSuccessful)
                return ParseXml(response);

            throw MakeError(response);
        }

        // Returns a valid session or throws
        internal static Session LoginWithOtp(string username,
                                             string password,
                                             int keyIterationCount,
                                             Ui.SecondFactorMethod method,
                                             ClientInfo clientInfo,
                                             Ui ui,
                                             RestClient rest)
        {
            // TODO: Support cancellation
            var otp = ui.ProvideSecondFactorPassword(method);
            var response = PerformSingleLoginRequest(username,
                                                     password,
                                                     keyIterationCount,
                                                     new Dictionary<string, object> {["otp"] = otp},
                                                     clientInfo,
                                                     rest);
            var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
            if (session != null)
                return session;

            throw MakeLoginError(response);
        }

        // Returns a valid session or throws
        internal static Session LoginWithOob(string username,
                                             string password,
                                             int keyIterationCount,
                                             Ui.OutOfBandMethod method,
                                             ClientInfo clientInfo,
                                             Ui ui,
                                             RestClient rest)
        {
            var extraParameters = new Dictionary<string, object> {["outofbandrequest"] = 1};

            ui.AskToApproveOutOfBand(method);
            for (;;)
            {
                var response = PerformSingleLoginRequest(username,
                                                         password,
                                                         keyIterationCount,
                                                         extraParameters,
                                                         clientInfo,
                                                         rest);
                var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    return session;

                if (GetOptionalErrorAttribute(response, "cause") != "outofbandrequired")
                    throw MakeLoginError(response);

                // Retry
                extraParameters["outofbandretry"] = "1";
                extraParameters["outofbandretryid"] = GetErrorAttribute(response, "retryid");
            }
        }

        internal static void MarkDeviceAsTrusted(Session session, ClientInfo clientInfo, RestClient rest)
        {
            var response = rest.PostForm("trust.php",
                                         new Dictionary<string, object>
                                         {
                                             ["uuid"] = clientInfo.Id,
                                             ["trustlabel"] = clientInfo.Description,
                                             ["token"] = session.Token,
                                         },
                                         cookies: GetSessionCookies(session));
            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static void Logout(Session session, RestClient rest)
        {
            var response = rest.PostForm("logout.php",
                                         new Dictionary<string, object>
                                         {
                                             ["method"] = PlatformToUserAgent[session.Platform],
                                             ["noredirect"] = 1,
                                         },
                                         cookies: GetSessionCookies(session));

            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static Dictionary<string, string> GetSessionCookies(Session session)
        {
            return new Dictionary<string, string> {["PHPSESSID"] = Uri.EscapeDataString(session.Id)};
        }

        internal static XDocument ParseXml(RestResponse<string> response)
        {
            try
            {
                return XDocument.Parse(response.Content);
            }
            catch (XmlException e)
            {
                throw new InternalErrorException($"Failed to parse XML in response from {response.RequestUri}", e);
            }
        }

        internal static Session ExtractSessionFromLoginResponse(XDocument response,
                                                                int keyIterationCount,
                                                                ClientInfo clientInfo)
        {
            var ok = response.XPathSelectElement("response/ok");
            if (ok == null)
                return null;

            var sessionId = ok.Attribute("sessionid");
            if (sessionId == null)
                return null;

            var token = ok.Attribute("token");
            if (token == null)
                return null;

            return new Session(sessionId.Value,
                               keyIterationCount,
                               token.Value,
                               clientInfo.Platform,
                               GetEncryptedPrivateKey(ok));
        }

        internal static Ui.OutOfBandMethod ExtractOobMethodFromLoginResponse(XDocument response)
        {
            var type = GetErrorAttribute(response, "outofbandtype");
            if (KnownOobMethods.TryGetValue(type, out var oobMethod))
                return oobMethod;

            var name = GetOptionalErrorAttribute(response, "outofbandname");
            throw new UnsupportedFeatureException($"Out-of-band method '{name ?? type}' is not supported");
        }

        internal static string GetEncryptedPrivateKey(XElement ok)
        {
            var attribute = ok.Attribute("privatekeyenc");

            // Returned value could be missing or blank. In both of these cases we need null.
            if (attribute == null || attribute.Value.IsNullOrEmpty())
                return null;

            return attribute.Value;
        }

        // returns a valid string or throws
        internal static string GetErrorAttribute(XDocument response, string name)
        {
            var attribute = GetOptionalErrorAttribute(response, name);
            if (attribute != null)
                return attribute;

            throw new InternalErrorException($"Unknown response schema: attribute '{name}' is missing");
        }

        internal static string GetOptionalErrorAttribute(XDocument response, string name)
        {
            return response
                .XPathSelectElement("response/error")?
                .Attribute(name)?
                .Value;
        }

        internal static Account[] ParseVault(Blob blob, byte[] encryptionKey)
        {
            return ParserHelper.WithBytes(
                blob.Bytes,
                reader =>
                {
                    var chunks = ParserHelper.ExtractChunks(reader);
                    if (!IsComplete(chunks))
                        throw new ParseException(ParseException.FailureReason.CorruptedBlob, "Blob is truncated");

                    var privateKey = new RSAParameters();
                    if (blob.EncryptedPrivateKey != null)
                        privateKey = ParserHelper.ParseEncryptedPrivateKey(blob.EncryptedPrivateKey, encryptionKey);

                    return ParseAccounts(chunks, encryptionKey, privateKey);
                });
        }

        internal static bool IsComplete(List<ParserHelper.Chunk> chunks)
        {
            return chunks.Count > 0 &&
                   chunks.Last().Id == "ENDM" &&
                   chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        internal static Account[] ParseAccounts(List<ParserHelper.Chunk> chunks,
                                                byte[] encryptionKey,
                                                RSAParameters privateKey)
        {
            var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));
            SharedFolder folder = null;

            foreach (var i in chunks)
            {
                switch (i.Id)
                {
                case "ACCT":
                    var account = ParserHelper.Parse_ACCT(
                        i,
                        folder == null ? encryptionKey : folder.EncryptionKey,
                        folder);

                    if (account != null)
                        accounts.Add(account);
                    break;
                case "SHAR":
                    folder = ParserHelper.Parse_SHAR(i, encryptionKey, privateKey);
                    break;
                }
            }

            return accounts.ToArray();
        }

        //
        // Private
        //

        private static Exception MakeError(RestResponse response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error has occurred", response.Error);

            if (response.IsHttpOk)
                return new InternalErrorException($"HTTP request to '{response.RequestUri}' failed", response.Error);

            return new InternalErrorException(
                $"HTTP request to '{response.RequestUri}' failed with status {response.StatusCode}",
                response.Error);
        }

        private static Exception MakeLoginError(XDocument response)
        {
            return new InternalErrorException("TODO");
        }

        //
        // Data
        //

        private static readonly Dictionary<Platform, string> PlatformToUserAgent = new Dictionary<Platform, string>
        {
            [Platform.Desktop] = "cli",
            [Platform.Mobile] = "android",
        };

        private static readonly Dictionary<string, Ui.SecondFactorMethod> KnownOtpMethods =
            new Dictionary<string, Ui.SecondFactorMethod>
            {
                ["googleauthrequired"] = Ui.SecondFactorMethod.GoogleAuth,
                ["microsoftauthrequired"] = Ui.SecondFactorMethod.MicrosoftAuth,
                ["otprequired"] = Ui.SecondFactorMethod.Yubikey,
            };

        private static readonly Dictionary<string, Ui.OutOfBandMethod> KnownOobMethods =
            new Dictionary<string, Ui.OutOfBandMethod>
            {
                ["lastpassauth"] = Ui.OutOfBandMethod.LastPassAuth,
                ["toopher"] = Ui.OutOfBandMethod.Toopher,
                ["duo"] = Ui.OutOfBandMethod.Duo,
            };
    }
}
