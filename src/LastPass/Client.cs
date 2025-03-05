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
    internal static partial class Client
    {
        public const int MaxOtpAttempts = 3;
        public const int DefaultIterationCount = 100_100;

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
                var (state, rest) = await Login(lowerCaseUsername, password, clientInfo, ui, transport, tagLog, cancellationToken)
                    .ConfigureAwait(false);
                try
                {
                    var blob = await DownloadVault(state, rest, cancellationToken).ConfigureAwait(false);

                    var privateKey = new RSAParameters();
                    if (!state.Session.EncryptedPrivateKey.IsNullOrEmpty())
                        privateKey = Parser.ParseEncryptedPrivateKey(state.Session.EncryptedPrivateKey, state.EncryptionKey);

                    return ParseVault(blob, state.EncryptionKey, privateKey, options);
                }
                finally
                {
                    await Logout(state, rest, cancellationToken).ConfigureAwait(false);
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

        internal record LoginState(Session Session, Platform Platform, byte[] EncryptionKey) { }

        internal static async Task<(LoginState, RestClient)> Login(
            string username,
            string password,
            ClientInfo clientInfo,
            IAsyncUi ui,
            IRestTransport transport,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var rest = new RestClient(transport, "https://lastpass.com", logger: logger, useSystemJson: true);
            var extraParameters = new Dictionary<string, object>();

            // 0. Check if we need to do SSO login
            var loginInfo = await GetLoginInfo(username, rest, cancellationToken).ConfigureAwait(false);
            if (loginInfo.LoginType != Model.LoginType.Regular)
                (password, extraParameters) = await PerformSsoLogin(username, loginInfo, clientInfo, ui, rest, cancellationToken)
                    .ConfigureAwait(false);

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
            var keyIterationCount = DefaultIterationCount;

            var changedIterationCount = false;
            var changedServer = false;
            var forceMfaMethod = MfaMethod.None;

            while (true)
            {
                var key = Util.DeriveKey(username, password, keyIterationCount);
                var keyHash = Util.DeriveKeyHash(username, password, keyIterationCount).ToHex();

                // 2. Knowing the iterations count we can hash the password and log in.
                //    On the first attempt simply with the username and password.
                var response = await PerformSingleLoginRequest(
                        username,
                        keyHash,
                        keyIterationCount,
                        forceMfaMethod,
                        false,
                        extraParameters,
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();

                var session = ExtractSessionFromLoginResponse(response);
                if (session != null)
                    // Set the key
                    return (new LoginState(session, clientInfo.Platform, key), rest);

                // 3. It's possible we're being redirected to another region.
                var server = GetOptionalErrorAttribute(response, "server");
                if (!server.IsNullOrEmpty())
                {
                    // Prevent infinite loops
                    if (changedServer)
                        throw new InternalErrorException("Trying to change server too many times");

                    // Change the server and retry
                    rest = new RestClient(transport, "https://" + server);
                    changedServer = true;
                    continue;
                }

                // 4. It's possible for the request above to come back with the correct iteration count.
                //    In this case we have to parse and repeat.
                var correctIterationCount = GetOptionalErrorAttribute(response, "iterations");
                if (!correctIterationCount.IsNullOrEmpty())
                {
                    // Prevent infinite loops
                    if (changedIterationCount)
                        throw new InternalErrorException("Trying to change iteration count too many times");

                    if (!int.TryParse(correctIterationCount, out keyIterationCount))
                        throw new InternalErrorException($"Failed to parse the iteration count, expected an integer value '{correctIterationCount}'");

                    // Change the iteration count and retry
                    changedIterationCount = true;
                    continue;
                }

                // 5. The simple login failed. This is usually due to some error, invalid credentials or
                //    a multifactor authentication being enabled.
                var cause = GetOptionalErrorAttribute(response, "cause");
                if (cause == null)
                    throw MakeLoginError(response);

                var enabledMfaMethods = ParseAvailableMfaMethods(response);
                OneOf<Session, MfaMethod> mfaLoginResult;

                // 6.1. One-time-password is required
                if (KnownOtpMethods.TryGetValue(cause, out var otpMethod))
                {
                    mfaLoginResult = await LoginWithOtp(
                            username,
                            password,
                            keyIterationCount,
                            otpMethod,
                            enabledMfaMethods.Where(x => x != otpMethod).ToArray(),
                            clientInfo,
                            ui,
                            rest,
                            cancellationToken
                        )
                        .ConfigureAwait(false);

                    cancellationToken.ThrowIfCancellationRequested();
                }
                // 6.2. Some out-of-bound authentication is enabled. This might or might not require
                //      additional input from the user depending on the method.
                else if (cause == "outofbandrequired")
                {
                    var allAttributes = GetAllErrorAttributes(response);
                    if (!allAttributes.TryGetValue("outofbandtype", out var oobMethodName))
                        throw new InternalErrorException("Out of band method is not specified");

                    if (!KnownMfaMethods.TryGetValue(oobMethodName, out var oobMethod))
                        throw new InternalErrorException($"Unsupported out of band method: {oobMethodName}");

                    mfaLoginResult = await LoginWithOob(
                            username,
                            password,
                            keyIterationCount,
                            allAttributes,
                            oobMethod,
                            enabledMfaMethods.Where(x => x != oobMethod).ToArray(),
                            clientInfo,
                            ui,
                            rest,
                            logger,
                            cancellationToken
                        )
                        .ConfigureAwait(false);

                    cancellationToken.ThrowIfCancellationRequested();
                }
                else
                {
                    throw MakeLoginError(response);
                }

                switch (mfaLoginResult.Value)
                {
                    // All good, we got a valid session
                    case Session s:
                        return (new LoginState(s, clientInfo.Platform, key), rest);
                    case MfaMethod mfaMethod:
                        // We need to retry the login with a different MFA method
                        forceMfaMethod = mfaMethod;
                        continue;
                }

                throw new InternalErrorException("Logic error: should never get here");
            }
        }

        internal static async Task<XDocument> PerformSingleLoginRequest(
            string username,
            string keyHash,
            int keyIterationCount,
            MfaMethod forceMfaMethod,
            bool rememberMe,
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
                ["hash"] = keyHash,
                ["iterations"] = keyIterationCount,
                ["includeprivatekeyenc"] = "1",
                ["outofbandsupported"] = "1",
                ["uuid"] = clientInfo.Id,
            };

            if (rememberMe)
            {
                parameters["trustlabel"] = clientInfo.Description;
                parameters["canexpire"] = "1";
                parameters["cansetuuid"] = "0";
            }

            if (forceMfaMethod != MfaMethod.None)
                parameters["provider"] = GetMfaMethodName(forceMfaMethod);

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
            string keyHash,
            int keyIterationCount,
            MfaMethod method,
            MfaMethod[] otherMethods,
            ClientInfo clientInfo,
            IAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            for (var attempt = 0; ; attempt++)
            {
                var otpResult = method switch
                {
                    MfaMethod.GoogleAuthenticator => await ui.ProvideGoogleAuthPasscode(attempt, otherMethods, cancellationToken)
                        .ConfigureAwait(false),
                    MfaMethod.MicrosoftAuthenticator => await ui.ProvideMicrosoftAuthPasscode(attempt, otherMethods, cancellationToken)
                        .ConfigureAwait(false),
                    MfaMethod.YubikeyOtp => await ui.ProvideYubikeyPasscode(attempt, otherMethods, cancellationToken).ConfigureAwait(false),
                    _ => throw new InternalErrorException("Invalid OTP method"),
                };

                switch (otpResult.Value)
                {
                    case MfaMethod mfa:
                        return mfa;
                    case Canceled:
                        throw new CanceledMultiFactorException("Second factor step is canceled by the user");
                }

                // User provided a passcode
                var otp = otpResult.AsT0;

                var response = await PerformSingleLoginRequest(
                        username,
                        keyHash,
                        keyIterationCount,
                        method,
                        otp.RememberMe,
                        new Dictionary<string, object> { ["otp"] = otp.Passcode },
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                var session = ExtractSessionFromLoginResponse(response);
                if (session != null)
                {
                    if (otp.RememberMe)
                        await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

                    return session;
                }

                var error = MakeLoginError(response);
                if (error is BadMultiFactorException && attempt < MaxOtpAttempts - 1)
                    continue;

                throw error;
            }
        }

        // Returns a valid session or throws
        internal static async Task<OneOf<Session, MfaMethod>> LoginWithOob(
            string username,
            string keyHash,
            int keyIterationCount,
            Dictionary<string, string> parameters,
            MfaMethod method,
            MfaMethod[] otherMethods,
            ClientInfo clientInfo,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var oobResult = await ApproveOob(username, parameters, method, otherMethods, ui, rest, logger, cancellationToken).ConfigureAwait(false);

            // The user chose a different MFA method
            if (oobResult.Value is MfaMethod mfa)
                return mfa;

            var rememberMe = false;
            var extraParameters = new Dictionary<string, object>();
            oobResult.Switch(
                otp =>
                {
                    extraParameters = extraParameters.MergeCopy(otp.Extras);
                    extraParameters["otp"] = otp.Otp.Passcode;
                    rememberMe = otp.Otp.RememberMe;
                },
                waitForOob =>
                {
                    extraParameters["outofbandrequest"] = 1;
                    rememberMe = waitForOob.RememberMe;
                },
                _ =>
                {
                    // Do nothing, already handled above
                }
            );

            Session session;
            while (true)
            {
                // In case of the OOB auth the server doesn't respond instantly. This works more like a long poll.
                // The server times out in about 10 seconds so there's no need to back off.
                var response = await PerformSingleLoginRequest(
                        username,
                        keyHash,
                        keyIterationCount,
                        method,
                        rememberMe,
                        extraParameters,
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                session = ExtractSessionFromLoginResponse(response);
                if (session != null)
                    break;

                if (GetOptionalErrorAttribute(response, "cause") != "outofbandrequired")
                    throw MakeLoginError(response);

                // Retry
                extraParameters["outofbandretry"] = "1";
                extraParameters["outofbandretryid"] = GetErrorAttribute(response, "retryid");
            }

            if (rememberMe)
                await MarkDeviceAsTrusted(session, clientInfo, rest, cancellationToken).ConfigureAwait(false);

            return session;
        }

        internal record OtpWithExtras(Otp Otp, Dictionary<string, object> Extras)
        {
            public OtpWithExtras(Otp otp)
                : this(otp, []) { }
        }

        internal record RedirectToV1;

        internal static async Task<OneOf<OtpWithExtras, WaitForOutOfBand, MfaMethod>> ApproveOob(
            string username,
            Dictionary<string, string> parameters,
            MfaMethod method,
            MfaMethod[] otherMethods,
            IAsyncUi ui,
            RestClient rest,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            switch (method)
            {
                case MfaMethod.Duo:
                    if (parameters.GetOrDefault("preferduowebsdk", "") != "1")
                        throw new UnsupportedFeatureException("Duo is only supported via Duo Web SDK");

                    var duoResult = await ApproveDuoWebSdk(username, parameters, otherMethods, ui, rest, logger, cancellationToken)
                        .ConfigureAwait(false);
                    return duoResult.Match<OneOf<OtpWithExtras, WaitForOutOfBand, MfaMethod>>(otp => otp, mfa => mfa);

                case MfaMethod.LastPassAuthenticator:
                    var lpaResult = await ui.ApproveLastPassAuth(0, otherMethods, cancellationToken).ConfigureAwait(false);
                    return lpaResult.Match<OneOf<OtpWithExtras, WaitForOutOfBand, MfaMethod>>(
                        otp => new OtpWithExtras(otp),
                        waitForOob => waitForOob,
                        mfa => mfa,
                        cancelled => throw new CanceledMultiFactorException("Out of band step is canceled by the user")
                    );

                default:
                    throw new UnsupportedFeatureException($"Out of band method '{method}' is not supported");
            }
        }

        internal static async Task<OneOf<OtpWithExtras, MfaMethod>> ApproveDuoWebSdk(
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

                switch (v4Result.Value)
                {
                    case OtpWithExtras otp:
                        return otp;
                    case MfaMethod mfa:
                        return mfa;
                }

                // Fallthrough to V1.
            }

            // Legacy Duo V1. Won't be available after September 2024.
            var v1Result = await ApproveDuoWebSdkV1(
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

            // Wrap OTP with empty extras
            return v1Result.MapT0(otp => new OtpWithExtras(otp));
        }

        private static async Task<OneOf<Otp, MfaMethod>> ApproveDuoWebSdkV1(
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

            switch (duoResult.Value)
            {
                case MfaMethod mfa:
                    return mfa;
                case DuoCancelled:
                    throw new CanceledMultiFactorException("Duo V1 MFA step is canceled by the user");
            }

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

            return new Otp(passcode, result.RememberMe);
        }

        private static async Task<OneOf<OtpWithExtras, RedirectToV1, MfaMethod>> ApproveDuoWebSdkV4(
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

            switch (duoResult.Value)
            {
                // 2. Detect if we need to redirect to V1. This happens when the traditional prompt is enabled in the Duo
                //    admin panel. The Duo URL looks the same for both the traditional prompt and the new universal one.
                //    So we have no way of knowing this in advance. This only becomes evident after the first request to
                //    the Duo API.
                case DuoResult result when result == DuoResult.RedirectToV1:
                    return new RedirectToV1();
                case MfaMethod mfa:
                    return mfa;
                case DuoCancelled:
                    throw new CanceledMultiFactorException("Duo V4 MFA step is canceled by the user");
            }

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
                return new OtpWithExtras(
                    new Otp("duoWebSdkV4", duoResult.AsT0.RememberMe),
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

        internal static async Task Logout(LoginState state, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostFormAsync(
                    "logout.php",
                    new Dictionary<string, object> { ["method"] = PlatformToUserAgent[state.Platform], ["noredirect"] = 1 },
                    headers: RestClient.NoHeaders,
                    cookies: GetSessionCookies(state.Session),
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (response.IsSuccessful)
                return;

            throw MakeError(response);
        }

        internal static async Task<byte[]> DownloadVault(LoginState state, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.GetAsync(
                    GetVaultEndpoint(state.Platform),
                    headers: RestClient.NoHeaders,
                    cookies: GetSessionCookies(state.Session),
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

        // TODO: Log unsupported methods, don't just ignore them
        internal static MfaMethod[] ParseAvailableMfaMethods(XDocument response)
        {
            return (GetOptionalErrorAttribute(response, "enabled_providers") ?? "")
                .Split(',')
                .Select(x => KnownMfaMethods.GetValueOrDefault(x, MfaMethod.None))
                .Where(x => x != MfaMethod.None)
                .ToArray();
        }

        internal static Session ExtractSessionFromLoginResponse(XDocument response)
        {
            var ok = response.XPathSelectElement("//ok");
            if (ok == null)
                return null;

            var sessionId = ok.Attribute("sessionid");
            if (sessionId == null)
                return null;

            var token = ok.Attribute("token");
            if (token == null)
                return null;

            return new Session(sessionId.Value, token.Value, GetEncryptedPrivateKey(ok));
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

        internal static string GetMfaMethodName(MfaMethod method)
        {
            return method switch
            {
                MfaMethod.GoogleAuthenticator => "googleauth",
                MfaMethod.MicrosoftAuthenticator => "microsoftauth",
                MfaMethod.YubikeyOtp => "yubikey",

                MfaMethod.Duo => "duo",
                MfaMethod.LastPassAuthenticator => "lastpassauth",

                _ => throw new UnsupportedFeatureException($"Unsupported MFA method: {method}"),
            };
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
                    case "user_not_exists":
                        return new BadCredentialsException("Invalid username");

                    case "password_invalid":
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

        private static readonly Dictionary<string, MfaMethod> KnownMfaMethods =
            // All the methods found in the original JS code. Keep them commented out to make it easier
            // to see what's missing.
            new()
            {
                ["duo"] = MfaMethod.Duo,
                ["googleauth"] = MfaMethod.GoogleAuthenticator,
                // ["grid"] = ???,
                ["lastpassauth"] = MfaMethod.LastPassAuthenticator,
                // ["lastpassmfa"] = ???,
                // ["multifactor"] = ???,
                ["microsoftauth"] = MfaMethod.MicrosoftAuthenticator,
                // ["salesforcehash"] = ???,
                // ["secureauth"] = ???,
                // ["securid"] = ???,
                // ["sesame"] = ???,
                // ["symantecvip"] = ???,
                // ["toopher"] = ???,
                // ["transakt"] = ???,
                ["yubikey"] = MfaMethod.YubikeyOtp,
                // ["no_multifactor"] = ???,
                ["webauthn"] = MfaMethod.Fido2,
            };
    }
}
