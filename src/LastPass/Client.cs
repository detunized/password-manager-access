// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass.Ui;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.LastPass
{
    internal static class Client
    {
        public static async Task<Account[]> OpenVault(string username,
                                                      string password,
                                                      ClientInfo clientInfo,
                                                      IUi ui,
                                                      ParserOptions options,
                                                      RestAsync.Config restConfig,
                                                      CancellationToken cancellationToken)
        {
            var lowerCaseUsername = username.ToLowerInvariant();
            var (session, rest) = await Login(lowerCaseUsername, password, clientInfo, ui, restConfig, cancellationToken).ConfigureAwait(false);
            try
            {
                var blob = await DownloadVault(session, rest, cancellationToken).ConfigureAwait(false);
                var key = Util.DeriveKey(lowerCaseUsername, password, session.KeyIterationCount);

                var privateKey = new RSAParameters();
                if (!session.EncryptedPrivateKey.IsNullOrEmpty())
                    privateKey = Parser.ParseEncryptedPrivateKey(session.EncryptedPrivateKey, key);

                return ParseVault(blob, key, privateKey, options);
            }
            finally
            {
                await Logout(session, rest, cancellationToken).ConfigureAwait(false);
            }
        }

        //
        // Internal
        //

        internal static async Task<(Session, RestClient)> Login(string username,
                                                                string password,
                                                                ClientInfo clientInfo,
                                                                IUi ui,
                                                                RestAsync.Config config,
                                                                CancellationToken cancellationToken)
        {
            var rest = RestAsync.Create("https://lastpass.com", config);

            // 1. First we need to request PBKDF2 key iteration count.
            //
            // We no longer request the iteration count from the server in a separate request because it
            // started to fail in weird ways. It seems there's a special combination or the UA and cookies
            // that returns the correct result. And that is not 100% reliable. After two or three attempts
            // it starts to fail again with an incorrect result.
            //
            // So we just went back a few years to the original way LastPass used to handle the iterations.
            // Namely, submit the default value and if it fails, the error would contain the correct value:
            // <response><error iterations="5000" /></response>
            var keyIterationCount = 100100;

            XDocument response = null;
            Session session = null;

            // We have a maximum of 3 retries in case we need to try again with the correct domain and/or
            // the number of KDF iterations the second/third time around.
            for (var i = 0; i < 3; i++)
            {
                // 2. Knowing the iterations count we can hash the password and log in.
                //    On the first attempt simply with the username and password.
                response = await PerformSingleLoginRequest(username,
                                                           password,
                                                           keyIterationCount,
                                                           new Dictionary<string, object>(),
                                                           clientInfo,
                                                           rest,
                                                           cancellationToken).ConfigureAwait(false);

                session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    return (session, rest);

                // It's possible we're being redirected to another region.
                var server = GetOptionalErrorAttribute(response, "server");
                if (!server.IsNullOrEmpty())
                {
                    rest = RestAsync.Create("https://" + server, config);
                    continue;
                }

                // It's possible for the request above to come back with the correct iteration count.
                // In this case we have to parse and repeat.
                var correctIterationCount = GetOptionalErrorAttribute(response, "iterations");
                if (correctIterationCount == null)
                    break;

                if (!int.TryParse(correctIterationCount, out keyIterationCount))
                    throw new InternalErrorException($"Failed to parse the iteration count, expected an integer value '{correctIterationCount}'");
            }

            // 3. The simple login failed. This is usually due to some error, invalid credentials or
            //    a multifactor authentication being enabled.
            var cause = GetOptionalErrorAttribute(response, "cause");
            if (cause == null)
                throw MakeLoginError(response);

            // 3.1. One-time-password is required
            if (KnownOtpMethods.TryGetValue(cause, out var otpMethod))
                session = await LoginWithOtp(username,
                                             password,
                                             keyIterationCount,
                                             otpMethod,
                                             clientInfo,
                                             ui,
                                             rest,
                                             cancellationToken).ConfigureAwait(false);

            // 3.2. Some out-of-bound authentication is enabled. This does not require any
            //      additional input from the user.
            else if (cause == "outofbandrequired")
                session = await LoginWithOob(username,
                                             password,
                                             keyIterationCount,
                                             GetAllErrorAttributes(response),
                                             clientInfo,
                                             ui,
                                             rest,
                                             cancellationToken).ConfigureAwait(false);

            // Nothing worked
            if (session == null)
                throw MakeLoginError(response);

            // All good
            return (session, rest);
        }

        internal static async Task<XDocument> PerformSingleLoginRequest(string username,
                                                                        string password,
                                                                        int keyIterationCount,
                                                                        Dictionary<string, object> extraParameters,
                                                                        ClientInfo clientInfo,
                                                                        RestClient rest,
                                                                        CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, object>
            {
                ["method"] = PlatformToUserAgent[clientInfo.Platform],
                ["xml"] = "2",
                ["username"] = username,
                ["hash"] = Util.DeriveKeyHash(username, password, keyIterationCount).ToHex(),
                ["iterations"] = keyIterationCount,
                ["includeprivatekeyenc"] = "1",
                ["outofbandsupported"] = "1",
                ["uuid"] = clientInfo.Id,
                ["trustlabel"] = clientInfo.Description, // TODO: Test against the real server if it's ok to send this every time!
            };

            foreach (var kv in extraParameters)
                parameters[kv.Key] = kv.Value;

            var response = await rest.PostForm("login.php",
                                               parameters,
                                               headers: new Dictionary<string, string>(),
                                               cookies: new Dictionary<string, string>(),
                                               cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return ParseXml(response);

            throw MakeError(response);
        }

        internal enum OtpMethod
        {
            GoogleAuth,
            MicrosoftAuth,
            Yubikey,
        }

        // Returns a valid session or throws
        internal static async Task<Session> LoginWithOtp(string username,
                                                         string password,
                                                         int keyIterationCount,
                                                         OtpMethod method,
                                                         ClientInfo clientInfo,
                                                         IUi ui,
                                                         RestClient rest,
                                                         CancellationToken cancellationToken)
        {
            var passcode = method switch
            {
                OtpMethod.GoogleAuth => ui.ProvideGoogleAuthPasscode(),
                OtpMethod.MicrosoftAuth => ui.ProvideMicrosoftAuthPasscode(),
                OtpMethod.Yubikey => ui.ProvideYubikeyPasscode(),
                _ => throw new InternalErrorException("Invalid OTP method")
            };

            if (passcode == OtpResult.Cancel)
                throw new CanceledMultiFactorException("Second factor step is canceled by the user");

            var response = await PerformSingleLoginRequest(username,
                                                           password,
                                                           keyIterationCount,
                                                           new Dictionary<string, object> { ["otp"] = passcode.Passcode },
                                                           clientInfo,
                                                           rest,
                                                           cancellationToken).ConfigureAwait(false);

            var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
            if (session == null)
                throw MakeLoginError(response);

            if (passcode.RememberMe)
                await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

            return session;
        }

        // Returns a valid session or throws
        internal static async Task<Session> LoginWithOob(string username,
                                                         string password,
                                                         int keyIterationCount,
                                                         Dictionary<string, string> parameters,
                                                         ClientInfo clientInfo,
                                                         IUi ui,
                                                         RestClient rest,
                                                         CancellationToken cancellationToken)
        {
            var oob = await ApproveOob(username, parameters, ui, rest, cancellationToken).ConfigureAwait(false);

            var result = oob.Result;
            if (result == OobResult.Cancel)
                throw new CanceledMultiFactorException("Out of band step is canceled by the user");

            var extraParameters = new Dictionary<string, object>(oob.Extras);
            if (result.WaitForOutOfBand)
                extraParameters["outofbandrequest"] = 1;
            else
                extraParameters["otp"] = result.Passcode;

            Session session;
            for (;;)
            {
                // In case of the OOB auth the server doesn't respond instantly. This works more like a long poll.
                // The server times out in about 10 seconds so there's no need to back off.
                var response = await PerformSingleLoginRequest(username,
                                                               password,
                                                               keyIterationCount,
                                                               extraParameters,
                                                               clientInfo,
                                                               rest, cancellationToken).ConfigureAwait(false);

                session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    break;

                if (GetOptionalErrorAttribute(response, "cause") != "outofbandrequired")
                    throw MakeLoginError(response);

                // Retry
                extraParameters["outofbandretry"] = "1";
                extraParameters["outofbandretryid"] = GetErrorAttribute(response, "retryid");
            }

            if (result.RememberMe)
                await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

            return session;
        }

        // This is used to pass the extra params along with the OOB result
        internal struct OobWithExtras
        {
            // This is a special sentinel value to mark the Duo V4 to V1 redirect
            public static readonly OobResult DuoV4ToV1Redirect = OobResult.ContinueWithPasscode("duo-v4-to-v1-redirect", false);

            public readonly OobResult Result;
            public readonly Dictionary<string, object> Extras;

            public OobWithExtras(OobResult result, Dictionary<string, object> extras = null)
            {
                Result = result;
                Extras = extras ?? new Dictionary<string, object>();
            }
        }

        internal static async Task<OobWithExtras> ApproveOob(string username,
                                                             Dictionary<string, string> parameters,
                                                             IUi ui,
                                                             RestClient rest,
                                                             CancellationToken cancellationToken)
        {
            if (!parameters.TryGetValue("outofbandtype", out var method))
                throw new InternalErrorException("Out of band method is not specified");

            return method switch
            {
                "lastpassauth" => new OobWithExtras(ui.ApproveLastPassAuth()),
                "duo" => await ApproveDuo(username, parameters, ui, rest, cancellationToken).ConfigureAwait(false),
                "salesforcehash" => new OobWithExtras(ui.ApproveSalesforceAuth()),
                _ => throw new UnsupportedFeatureException($"Out of band method '{method}' is not supported")
            };
        }

        internal static async Task<OobWithExtras> ApproveDuo(string username,
                                                             Dictionary<string, string> parameters,
                                                             IUi ui,
                                                             RestClient rest,
                                                             CancellationToken cancellationToken)
        {
            return parameters.GetOrDefault("preferduowebsdk", "") == "1"
                ? await ApproveDuoWebSdk(username, parameters, ui, rest, cancellationToken).ConfigureAwait(false)
                : new OobWithExtras(ui.ApproveDuo());
        }

        internal static async Task<OobWithExtras> ApproveDuoWebSdk(string username,
                                                                   Dictionary<string, string> parameters,
                                                                   IUi ui,
                                                                   RestClient rest,
                                                                   CancellationToken cancellationToken)
        {
            string GetParam(string name)
            {
                if (parameters.TryGetValue(name, out var value))
                    return value;

                throw new InternalErrorException($"Invalid response: '{name}' parameter not found");
            }

            // See if V4 is enabled
            if (parameters.TryGetValue("duo_authentication_url", out var url))
            {
                var result = await ApproveDuoWebSdkV4(username: username,
                                                      url: url,
                                                      sessionToken: GetParam("duo_session_token"),
                                                      privateToken: GetParam("duo_private_token"),
                                                      ui: ui,
                                                      rest: rest,
                                                      cancellationToken: cancellationToken).ConfigureAwait(false);

                // If we're not redirected to V1, we're done. Otherwise, fallthrough to V1.
                if (result.Result != OobWithExtras.DuoV4ToV1Redirect)
                    return result;
            }

            // Legacy Duo V1. Won't be available after September 2024.
            return await ApproveDuoWebSdkV1(username: username,
                                            host: GetParam("duo_host"),
                                            salt: GetParam("duo_bytes"),
                                            signature: GetParam("duo_signature"),
                                            ui: ui,
                                            rest: rest,
                                            cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        private static async Task<OobWithExtras> ApproveDuoWebSdkV1(string username,
                                                                    string host,
                                                                    string salt,
                                                                    string signature,
                                                                    IUi ui,
                                                                    RestClient rest,
                                                                    CancellationToken cancellationToken)
        {
            // 1. Do a normal Duo V1 first
            var result = await DuoV1.Authenticate(host, signature, ui, rest, cancellationToken).ConfigureAwait(false);
            if (result == null)
                return new OobWithExtras(OobResult.Cancel);

            // 2. Exchange the signature for a passcode
            var passcode = await ExchangeDuoSignatureForPasscode(username: username,
                                                                 signature: result.Code,
                                                                 salt: salt,
                                                                 rest: rest,
                                                                 cancellationToken: cancellationToken).ConfigureAwait(false);

            return new OobWithExtras(OobResult.ContinueWithPasscode(passcode, result.RememberMe));
        }

        private static async Task<OobWithExtras> ApproveDuoWebSdkV4(string username,
                                                                    string url,
                                                                    string sessionToken,
                                                                    string privateToken,
                                                                    IUi ui,
                                                                    RestClient rest,
                                                                    CancellationToken cancellationToken)
        {
            // 1. Do a normal Duo V4 first
            var result = await DuoV4.Authenticate(url, ui, rest, cancellationToken).ConfigureAwait(false);
            if (result == null)
                return new OobWithExtras(OobResult.Cancel);

            // 2. Detect if we need to redirect to V1. This happens when the traditional prompt is enabled in the Duo
            //    admin panel. The Duo URL looks the same for both the traditional prompt and the new universal one.
            //    So we have no way of knowing this in advance. This only becomes evident after the first request to
            //    the Duo API.
            if (result == Result.RedirectToV1)
                return new OobWithExtras(OobWithExtras.DuoV4ToV1Redirect);

            // 3. Since LastPass is special we have to jump through some hoops to get this finalized
            //    Even though Duo already returned us the code, we need to poll LastPass to get a
            //    custom one-time token to submit it with the login request later.
            var lmiRest = RestAsync.Create("https://lastpass.com/lmiapi/duo", rest);
            var response = await lmiRest.PostJson<Model.DuoStatus>("status",
                                                                   new Dictionary<string, object>
                                                                   {
                                                                       ["userName"] = username,
                                                                       ["sessionToken"] = sessionToken,
                                                                       ["privateToken"] = privateToken,
                                                                   },
                                                                   headers: new Dictionary<string, string>(),
                                                                   cookies: new Dictionary<string, string>(),
                                                                   cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var status = response.Data;
            if (status.Status == "allowed" && !status.OneTimeToken.IsNullOrEmpty())
                return new OobWithExtras(OobResult.ContinueWithPasscode("duoWebSdkV4", result.RememberMe),
                                         new Dictionary<string, object>
                                         {
                                            ["provider"] = "duo",
                                            ["duoOneTimeToken"] = status.OneTimeToken,
                                            ["duoSessionToken"] = sessionToken,
                                            ["duoPrivateToken"] = privateToken,
                                         });

            throw new InternalErrorException("Failed to retrieve Duo one time token");
        }

        internal static async Task<string> ExchangeDuoSignatureForPasscode(string username,
                                                                           string signature,
                                                                           string salt,
                                                                           RestClient rest,
                                                                           CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, object>
            {
                ["xml"] = 1,
                ["akey"] = salt,
                ["username"] = username,
                ["uuid"] = "",
                ["canexpire"] = 1,
                ["cansetuuid"] = 1,
                ["trustlabel"] = "",
                ["sig_response"] = signature,
            };

            var response = await rest.PostForm<string>("duo.php",
                                                       parameters,
                                                       headers: new Dictionary<string, string>(),
                                                       cookies: new Dictionary<string, string>(),
                                                       cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return "checkduo" + ExtractDuoPasscodeFromDuoResponse(ParseXml(response));

            throw MakeError(response);
        }

        internal static string ExtractDuoPasscodeFromDuoResponse(XDocument response)
        {
            var code = response.Element("ok")?.Attribute("code")?.Value;
            if (code.IsNullOrEmpty())
                throw new InternalErrorException("Invalid response: ok/code not found");

            return code;
        }

        internal static async Task MarkDeviceAsTrusted(Session session, ClientInfo clientInfo, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostForm<string>("trust.php",
                                                       new Dictionary<string, object>
                                                       {
                                                           ["uuid"] = clientInfo.Id,
                                                           ["trustlabel"] = clientInfo.Description,
                                                           ["token"] = session.Token,
                                                       },
                                                       headers: new Dictionary<string, string>(),
                                                       cookies: GetSessionCookies(session),
                                                       cancellationToken: cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static async Task Logout(Session session, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostForm<string>("logout.php",
                                                       new Dictionary<string, object>
                                                       {
                                                           ["method"] = PlatformToUserAgent[session.Platform],
                                                           ["noredirect"] = 1,
                                                       },
                                                       headers: new Dictionary<string, string>(),
                                                       cookies: GetSessionCookies(session),
                                                       cancellationToken: cancellationToken).ConfigureAwait(false);

            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static async Task<byte[]> DownloadVault(Session session, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.Get<string>(GetVaultEndpoint(session.Platform),
                                                  parameters: new Dictionary<string, object>(),
                                                  headers: new Dictionary<string, string>(),
                                                  cookies: GetSessionCookies(session),
                                                  cancellationToken: cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return response.Content.Decode64();

            throw MakeError(response);
        }

        internal static string GetVaultEndpoint(Platform platform)
        {
            return $"getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc={PlatformToUserAgent[platform]}";
        }

        internal static Dictionary<string, string> GetSessionCookies(Session session)
        {
            return new Dictionary<string, string> {["PHPSESSID"] = Uri.EscapeDataString(session.Id)};
        }

        internal static XDocument ParseXml(RestSharp.RestResponse response)
        {
            try
            {
                return XDocument.Parse(response.Content ?? "");
            }
            catch (XmlException e)
            {
                throw new InternalErrorException($"Failed to parse XML in response from {response.Request.Resource}", e);
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

        internal static Dictionary<string, string> GetAllErrorAttributes(XDocument response)
        {
            return response
                .XPathSelectElement("response/error")?
                .Attributes()
                .ToDictionary(x => x.Name.LocalName, x => x.Value);
        }

        internal static Account[] ParseVault(byte[] blob, byte[] encryptionKey, RSAParameters privateKey, ParserOptions options)
        {
            return blob.Open(
                reader =>
                {
                    var chunks = Parser.ExtractChunks(reader);
                    if (!IsComplete(chunks))
                        throw new InternalErrorException("Blob is truncated or corrupted");

                    return ParseAccounts(chunks, encryptionKey, privateKey, options);
                });
        }

        internal static bool IsComplete(List<Parser.Chunk> chunks)
        {
            return chunks.Count > 0 &&
                   chunks.Last().Id == "ENDM" &&
                   chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        internal static Account[] ParseAccounts(List<Parser.Chunk> chunks,
                                                byte[] encryptionKey,
                                                RSAParameters privateKey,
                                                ParserOptions options)
        {
            var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));
            SharedFolder folder = null;

            foreach (var chunk in chunks)
            {
                switch (chunk.Id)
                {
                case "ACCT":
                    var account = Parser.Parse_ACCT(chunk,
                                                    folder == null ? encryptionKey : folder.EncryptionKey,
                                                    folder,
                                                    options);

                    if (account != null)
                        accounts.Add(account);
                    break;
                case "SHAR":
                    folder = Parser.Parse_SHAR(chunk, encryptionKey, privateKey);
                    break;
                }
            }

            return accounts.ToArray();
        }

        //
        // Error handling
        //

        internal static Exception MakeError<T>(RestSharp.RestResponse<T> response)
        {
            if (response.IsNetworkError())
                return new NetworkErrorException("Network error has occurred", response.ErrorException);

            if (response.IsSuccessStatusCode)
                return new InternalErrorException($"HTTP request to '{response.Request.Resource}' failed", response.ErrorException);

            return new InternalErrorException($"HTTP request to '{response.Request.Resource}' failed with status {response.StatusCode}",
                                              response.ErrorException);
        }

        // TODO: DRY up the code
        internal static Exception MakeError(RestSharp.RestResponse response)
        {
            if (response.IsNetworkError())
                return new NetworkErrorException("Network error has occurred", response.ErrorException);

            if (response.IsSuccessStatusCode)
                return new InternalErrorException($"HTTP request to '{response.Request.Resource}' failed", response.ErrorException);

            return new InternalErrorException($"HTTP request to '{response.Request.Resource}' failed with status {response.StatusCode}",
                                              response.ErrorException);
        }

        internal static BaseException MakeLoginError(XDocument response)
        {
            // XML is valid but there's nothing in it we can understand
            var error = response.XPathSelectElement("response/error");
            if (error == null)
                return new InternalErrorException("Unknown response schema");

            // Both of these are optional
            var cause = error.Attribute("cause");
            var message = error.Attribute("message");

            // We have a cause element, see if it's one of ones we know
            if (cause != null)
            {
                switch (cause.Value)
                {
                case "unknownemail":
                    return new BadCredentialsException("Invalid username");

                case "unknownpassword":
                    return new BadCredentialsException("Invalid password");

                case "googleauthfailed":
                case "microsoftauthfailed":
                case "otpfailed":
                    return new BadMultiFactorException("Second factor code is incorrect");

                case "multifactorresponsefailed":
                    return new BadMultiFactorException("Out of band authentication failed");

                default:
                    return new InternalErrorException(message?.Value ?? cause.Value);
                }
            }

            // No cause, maybe at least a message
            if (message != null)
                return new InternalErrorException(message.Value);

            // Nothing we know, just the error element
            return new InternalErrorException("Unknown error");
        }

        //
        // Data
        //

        private static readonly Dictionary<Platform, string> PlatformToUserAgent = new Dictionary<Platform, string>
        {
            [Platform.Desktop] = "cli",
            [Platform.Mobile] = "android",
        };

        private static readonly Dictionary<string, OtpMethod> KnownOtpMethods = new Dictionary<string, OtpMethod>
        {
            ["googleauthrequired"] = OtpMethod.GoogleAuth,
            ["microsoftauthrequired"] = OtpMethod.MicrosoftAuth,
            ["otprequired"] = OtpMethod.Yubikey,
        };
    }
}
