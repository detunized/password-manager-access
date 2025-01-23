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
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass
{
    internal static class Client
    {
        public static async Task<Account[]> OpenVault(
            string username,
            string password,
            ClientInfo clientInfo,
            IAsyncUi ui,
            IRestTransport transport,
            ParserOptions options,
            ISecureLogger logger, // can be null
            CancellationToken cancellationToken
        )
        {
            // We allow the logger to be null for optimization purposes
            var tagLog = options.LoggingEnabled ? new TaggedLogger("LastPass", logger ?? new NullLogger()) : null;

            // Add filters to the log
            if (tagLog != null)
            {
                tagLog.AddFilter(username);
                tagLog.AddFilter(username.EncodeUri());
                tagLog.AddFilter(username.EncodeUriData());
                tagLog.AddFilter(password);
                tagLog.AddFilter(password.EncodeUri());
                tagLog.AddFilter(password.EncodeUriData());
                tagLog.AddFilter(clientInfo.Id);
                tagLog.AddRegexFilter(@"(?<=hash=)[a-z0-9]+");
                tagLog.AddRegexFilter(@"(?<=PHPSESSID=)[a-z0-9]+");
                tagLog.AddRegexFilter(@"(?<=sessionid=)"".*?""");

                // TODO: Move to Duo
                tagLog.AddRegexFilter(@"(?<=duo_(session|private)_token=)"".*?""");
                tagLog.AddRegexFilter(@"(?<=Cookie: sid\|)[a-z0-9-]="".*?""");
                tagLog.AddRegexFilter(@"(?<=\bsid=)[a-z0-9%-]+");
                tagLog.AddRegexFilter(@"(?<=TX\|)[a-z0-9|:-]+");
                tagLog.AddRegexFilter(@"(?<=eyJ0eXAiOiJKV1QiL.*?\.)[a-z0-9.%_/+-]+"); // JWT tokens
            }

            try
            {
                var lowerCaseUsername = username.ToLowerInvariant();
                var (session, rest) = await Login(lowerCaseUsername, password, clientInfo, ui, transport, tagLog, cancellationToken)
                    .ConfigureAwait(false);
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
            catch (BaseException e)
            {
                if (tagLog != null)
                    e.Log = tagLog.Entries;

                throw;
            }
        }

        //
        // Internal
        //

        internal static async Task<(Session, RestClient)> Login(
            string username,
            string password,
            ClientInfo clientInfo,
            IAsyncUi ui,
            IRestTransport transport,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var rest = new RestClient(transport, "https://lastpass.com", logger: logger);

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
                response = await PerformSingleLoginRequest(username, password, keyIterationCount, [], clientInfo, rest, cancellationToken)
                    .ConfigureAwait(false);

                session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    return (session, rest);

                // It's possible we're being redirected to another region.
                var server = GetOptionalErrorAttribute(response, "server");
                if (!server.IsNullOrEmpty())
                {
                    rest = new RestClient(transport, "https://" + server);
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
            {
                var otpResult = await LoginWithOtp(
                        username,
                        password,
                        keyIterationCount,
                        otpMethod,
                        [], // TODO: Add other methods
                        clientInfo,
                        ui,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                if (otpResult.IsT1)
                    throw new NotImplementedException("MFA selection is not supported");

                session = otpResult.AsT0;
            }
            // 3.2. Some out-of-bound authentication is enabled. This does not require any
            //      additional input from the user.
            else if (cause == "outofbandrequired")
            {
                var oobResult = await LoginWithOob(
                        username,
                        password,
                        keyIterationCount,
                        GetAllErrorAttributes(response),
                        [], // TODO: Add other methods
                        clientInfo,
                        ui,
                        rest,
                        logger,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                if (oobResult.IsT1)
                    throw new NotImplementedException("MFA selection is not supported");

                session = oobResult.AsT0;
            }

            // Nothing worked
            if (session == null)
                throw MakeLoginError(response);

            // All good
            return (session, rest);
        }

        internal static async Task<XDocument> PerformSingleLoginRequest(
            string username,
            string password,
            int keyIterationCount,
            Dictionary<string, object> extraParameters,
            ClientInfo clientInfo,
            RestClient rest,
            CancellationToken cancellationToken
        )
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

            var response = await rest.PostFormAsync("login.php", parameters, cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return ParseXml(response);

            throw MakeError(response);
        }

        // Returns a valid session or throws
        internal static async Task<OneOf<Session, MfaMethod>> LoginWithOtp(
            string username,
            string password,
            int keyIterationCount,
            MfaMethod method,
            MfaMethod[] otherMethods,
            ClientInfo clientInfo,
            IAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var otpResult = method switch
            {
                MfaMethod.GoogleAuthenticator => await ui.ProvideGoogleAuthPasscode(otherMethods, cancellationToken).ConfigureAwait(false),
                MfaMethod.MicrosoftAuthenticator => await ui.ProvideMicrosoftAuthPasscode(otherMethods, cancellationToken).ConfigureAwait(false),
                MfaMethod.YubikeyOtp => await ui.ProvideYubikeyPasscode(otherMethods, cancellationToken).ConfigureAwait(false),
                _ => throw new InternalErrorException("Invalid OTP method"),
            };

            // User chose a different MFA method
            if (otpResult.IsT1)
                return otpResult.AsT1;

            // User cancelled
            if (otpResult.IsT2)
                throw new CanceledMultiFactorException("Second factor step is canceled by the user");

            // User provided a passcode
            var otp = otpResult.AsT0;

            var response = await PerformSingleLoginRequest(
                    username,
                    password,
                    keyIterationCount,
                    new Dictionary<string, object> { ["otp"] = otp.Passcode },
                    clientInfo,
                    rest,
                    cancellationToken
                )
                .ConfigureAwait(false);

            var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
            if (session == null)
                throw MakeLoginError(response);

            if (otp.RememberMe)
                await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

            return session;
        }

        // Returns a valid session or throws
        internal static async Task<OneOf<Session, MfaMethod>> LoginWithOob(
            string username,
            string password,
            int keyIterationCount,
            Dictionary<string, string> parameters,
            MfaMethod[] otherMethods,
            ClientInfo clientInfo,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var oobResult = await ApproveOob(username, parameters, otherMethods, ui, rest, logger, cancellationToken).ConfigureAwait(false);

            // The user chose a different MFA method
            if (oobResult.IsT1)
                return oobResult.AsT1;

            var result = oobResult.AsT0;

            var extraParameters = new Dictionary<string, object>(result.Extras);
            if (result.Result.WaitForOutOfBand)
                extraParameters["outofbandrequest"] = 1;
            else
                extraParameters["otp"] = result.Result.Passcode;

            Session session;
            for (; ; )
            {
                // In case of the OOB auth the server doesn't respond instantly. This works more like a long poll.
                // The server times out in about 10 seconds so there's no need to back off.
                var response = await PerformSingleLoginRequest(
                        username,
                        password,
                        keyIterationCount,
                        extraParameters,
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    break;

                if (GetOptionalErrorAttribute(response, "cause") != "outofbandrequired")
                    throw MakeLoginError(response);

                // Retry
                extraParameters["outofbandretry"] = "1";
                extraParameters["outofbandretryid"] = GetErrorAttribute(response, "retryid");
            }

            if (result.Result.RememberMe)
                await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

            return session;
        }

        // This is used to pass the extra params along with the OOB result
        internal struct OobWithExtras(OobResult result, Dictionary<string, object> extras = null)
        {
            // This is a special sentinel value to mark the Duo V4 to V1 redirect
            public static readonly OobResult DuoV4ToV1Redirect = new(false, "duo-v4-to-v1-redirect", false);

            public readonly OobResult Result = result;
            public readonly Dictionary<string, object> Extras = extras ?? [];
        }

        internal static async Task<OneOf<OobWithExtras, MfaMethod>> ApproveOob(
            string username,
            Dictionary<string, string> parameters,
            MfaMethod[] otherMethods,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            if (!parameters.TryGetValue("outofbandtype", out var method))
                throw new InternalErrorException("Out of band method is not specified");

            if (method == "duo" && parameters.GetOrDefault("preferduowebsdk", "") == "1")
                return await ApproveDuoWebSdk(username, parameters, otherMethods, ui, rest, logger, cancellationToken).ConfigureAwait(false);

            var oobResult = method switch
            {
                "lastpassauth" => await ui.ApproveLastPassAuth(otherMethods, cancellationToken).ConfigureAwait(false),
                "duo" => await ui.ApproveDuo(otherMethods, cancellationToken).ConfigureAwait(false),
                "salesforcehash" => await ui.ApproveSalesforceAuth(otherMethods, cancellationToken).ConfigureAwait(false),
                _ => throw new UnsupportedFeatureException($"Out of band method '{method}' is not supported"),
            };

            return oobResult.Match<OneOf<OobWithExtras, MfaMethod>>(
                oobResult => new OobWithExtras(oobResult),
                method => method,
                _ => throw new CanceledMultiFactorException("Out of band step is canceled by the user")
            );
        }

        internal static async Task<OneOf<OobWithExtras, MfaMethod>> ApproveDuoWebSdk(
            string username,
            Dictionary<string, string> parameters,
            MfaMethod[] otherMethods,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
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
                var v4Result = await ApproveDuoWebSdkV4(
                        username: username,
                        url: url,
                        sessionToken: GetParam("duo_session_token"),
                        privateToken: GetParam("duo_private_token"),
                        otherMethods: otherMethods,
                        ui: ui,
                        rest: rest,
                        logger: logger,
                        cancellationToken: cancellationToken
                    )
                    .ConfigureAwait(false);

                // The user chose a different MFA method
                if (v4Result.IsT1)
                    return v4Result.AsT1;

                // If we're not redirected to V1, we're done. Otherwise, fallthrough to V1.
                if (v4Result.AsT0.Result != OobWithExtras.DuoV4ToV1Redirect)
                    return v4Result.AsT0;
            }

            // Legacy Duo V1. Won't be available after September 2024.
            return await ApproveDuoWebSdkV1(
                    username: username,
                    host: GetParam("duo_host"),
                    salt: GetParam("duo_bytes"),
                    signature: GetParam("duo_signature"),
                    otherMethods: otherMethods,
                    ui: ui,
                    rest: rest,
                    logger: logger,
                    cancellationToken: cancellationToken
                )
                .ConfigureAwait(false);
        }

        private static async Task<OneOf<OobWithExtras, MfaMethod>> ApproveDuoWebSdkV1(
            string username,
            string host,
            string salt,
            string signature,
            MfaMethod[] otherMethods,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            // 1. Do a normal Duo V1 first
            // Allow the logger to be null for optimization purposes (saved a bunch of work in the RestClient code)
            var duoLogger = logger == null ? null : new TaggedLogger("LastPass.DuoV1", logger);
            var duoResult = await DuoV1
                .AuthenticateAsync(host, signature, otherMethods, ui, rest.Transport, duoLogger, cancellationToken)
                .ConfigureAwait(false);

            // User chose a different MFA method
            if (duoResult.IsT1)
                return duoResult.AsT1;

            // User cancelled
            if (duoResult.IsT2)
                throw new CanceledMultiFactorException("Duo V1 MFA step is canceled by the user");

            var result = duoResult.AsT0;

            // 2. Exchange the signature for a passcode
            var passcode = await ExchangeDuoSignatureForPasscode(
                    username: username,
                    signature: result.Code,
                    salt: salt,
                    rest: rest,
                    cancellationToken: cancellationToken
                )
                .ConfigureAwait(false);

            return new OobWithExtras(new(false, passcode, result.RememberMe));
        }

        private static async Task<OneOf<OobWithExtras, MfaMethod>> ApproveDuoWebSdkV4(
            string username,
            string url,
            string sessionToken,
            string privateToken,
            MfaMethod[] otherMethods,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            // 1. Do a normal Duo V4 first
            // Allow the logger to be null for optimization purposes (saved a bunch of work in the RestClient code)
            var duoLogger = logger == null ? null : new TaggedLogger("LastPass.DuoV4", logger);
            var duoResult = await DuoV4.AuthenticateAsync(url, otherMethods, ui, rest.Transport, duoLogger, cancellationToken).ConfigureAwait(false);

            // User chose a different MFA method
            if (duoResult.IsT1)
                return duoResult.AsT1;

            // User cancelled
            if (duoResult.IsT2)
                throw new CanceledMultiFactorException("Duo V4 MFA step is canceled by the user");

            var result = duoResult.AsT0;

            // 2. Detect if we need to redirect to V1. This happens when the traditional prompt is enabled in the Duo
            //    admin panel. The Duo URL looks the same for both the traditional prompt and the new universal one.
            //    So we have no way of knowing this in advance. This only becomes evident after the first request to
            //    the Duo API.
            if (result == Result.RedirectToV1)
                return new OobWithExtras(OobWithExtras.DuoV4ToV1Redirect);

            // 3. Since LastPass is special we have to jump through some hoops to get this finalized
            //    Even though Duo already returned us the code, we need to poll LastPass to get a
            //    custom one-time token to submit it with the login request later.
            var lmiRest = new RestClient(rest.Transport, "https://lastpass.com/lmiapi/duo");
            var response = await lmiRest
                .PostJsonAsync<Model.DuoStatus>(
                    "status",
                    new Dictionary<string, object>
                    {
                        ["userName"] = username,
                        ["sessionToken"] = sessionToken,
                        ["privateToken"] = privateToken,
                    },
                    cancellationToken
                )
                .ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var status = response.Data;
            if (status.Status == "allowed" && !status.OneTimeToken.IsNullOrEmpty())
                return new OobWithExtras(
                    new(false, "duoWebSdkV4", result.RememberMe),
                    new Dictionary<string, object>
                    {
                        ["provider"] = "duo",
                        ["duoOneTimeToken"] = status.OneTimeToken,
                        ["duoSessionToken"] = sessionToken,
                        ["duoPrivateToken"] = privateToken,
                    }
                );

            throw new InternalErrorException("Failed to retrieve Duo one time token");
        }

        internal static async Task<string> ExchangeDuoSignatureForPasscode(
            string username,
            string signature,
            string salt,
            RestClient rest,
            CancellationToken cancellationToken
        )
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

            var response = await rest.PostFormAsync("duo.php", parameters, cancellationToken).ConfigureAwait(false);
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
            var response = await rest.PostFormAsync(
                    "trust.php",
                    new Dictionary<string, object>
                    {
                        ["uuid"] = clientInfo.Id,
                        ["trustlabel"] = clientInfo.Description,
                        ["token"] = session.Token,
                    },
                    headers: RestClient.NoHeaders,
                    cookies: GetSessionCookies(session),
                    cancellationToken
                )
                .ConfigureAwait(false);
            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static async Task Logout(Session session, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostFormAsync(
                    "logout.php",
                    new Dictionary<string, object> { ["method"] = PlatformToUserAgent[session.Platform], ["noredirect"] = 1 },
                    headers: RestClient.NoHeaders,
                    cookies: GetSessionCookies(session),
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static async Task<byte[]> DownloadVault(Session session, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.GetAsync(
                    GetVaultEndpoint(session.Platform),
                    headers: RestClient.NoHeaders,
                    cookies: GetSessionCookies(session),
                    cancellationToken
                )
                .ConfigureAwait(false);
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
            return new Dictionary<string, string> { ["PHPSESSID"] = Uri.EscapeDataString(session.Id) };
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

        internal static Session ExtractSessionFromLoginResponse(XDocument response, int keyIterationCount, ClientInfo clientInfo)
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

            return new Session(sessionId.Value, keyIterationCount, token.Value, clientInfo.Platform, GetEncryptedPrivateKey(ok));
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
            return response.XPathSelectElement("response/error")?.Attribute(name)?.Value;
        }

        internal static Dictionary<string, string> GetAllErrorAttributes(XDocument response)
        {
            return response.XPathSelectElement("response/error")?.Attributes().ToDictionary(x => x.Name.LocalName, x => x.Value);
        }

        internal static Account[] ParseVault(byte[] blob, byte[] encryptionKey, RSAParameters privateKey, ParserOptions options)
        {
            return blob.Open(reader =>
            {
                var chunks = Parser.ExtractChunks(reader);
                if (!IsComplete(chunks))
                    throw new InternalErrorException("Blob is truncated or corrupted");

                return ParseAccounts(chunks, encryptionKey, privateKey, options);
            });
        }

        internal static bool IsComplete(List<Parser.Chunk> chunks)
        {
            return chunks.Count > 0 && chunks.Last().Id == "ENDM" && chunks.Last().Payload.SequenceEqual("OK".ToBytes());
        }

        internal static Account[] ParseAccounts(List<Parser.Chunk> chunks, byte[] encryptionKey, RSAParameters privateKey, ParserOptions options)
        {
            var accounts = new List<Account>(chunks.Count(i => i.Id == "ACCT"));
            SharedFolder folder = null;

            foreach (var chunk in chunks)
            {
                switch (chunk.Id)
                {
                    case "ACCT":
                        var account = Parser.Parse_ACCT(chunk, folder == null ? encryptionKey : folder.EncryptionKey, folder, options);

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
        // Private
        //

        private static Exception MakeError(RestResponse response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error has occurred", response.Error);

            if (response.IsHttpOk)
                return new InternalErrorException($"HTTP request to '{response.RequestUri}' failed", response.Error);

            return new InternalErrorException($"HTTP request to '{response.RequestUri}' failed with status {response.StatusCode}", response.Error);
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

        private static readonly Dictionary<string, MfaMethod> KnownOtpMethods =
            new()
            {
                ["googleauthrequired"] = MfaMethod.GoogleAuthenticator,
                ["microsoftauthrequired"] = MfaMethod.MicrosoftAuthenticator,
                ["otprequired"] = MfaMethod.YubikeyOtp,
            };
    }
}
