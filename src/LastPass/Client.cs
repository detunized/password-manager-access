// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
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
        public const int MaxOtpAttempts = 3;

        // SSO flow
        //
        // 1. Check the login type:
        //    GET: https://lastpass.com/lmiapi/login/type?username=dmitry%40downhillpro.xyz
        //    Response: {"type": 3}
        //      - type should be 3
        //      - type <= 2 is getPasswordSaml (a different form of SSO)
        //      - Azure is handled differently

        // 2. Go to OpenIDConnectAuthority (https://login.microsoftonline.com/4c5a5ec1-9ac5-4612-9b4c-6bed178bb65a/v2.0/.well-known/openid-configuration)
        //    to get the config:

        // 3. Perform SSO login
        //    https://login.microsoftonline.com/4c5a5ec1-9ac5-4612-9b4c-6bed178bb65a/oauth2/v2.0/authorize?
        //      client_id=51a5546b-7676-48f3-afcf-8c15b94ccdc2
        //      redirect_uri=https%3A%2F%2Faccounts.lastpass.com%2Ffederated%2Foidcredirect.html
        //      response_type=code
        //      scope=openid%20email%20profile
        //      state=c01d06db5bc04b83b2274d767a8f8176
        //      code_challenge=d3QPUhlIoYSCB1-H8PStoFfN4Bfyb5Dld6xH04hsxtY
        //      code_challenge_method=S256
        //      response_mode=fragment
        //      login_hint=dmitry%40downhillpro.xyz

        // response_type:
        //  - if PkceEnabled: "code"
        //  - else: "id_token token"

        // response_mode:
        //  - if PkceEnabled && Provider !== e.OIDC_PROVIDERS.PingOne : "fragment"
        //  - else: null

        // e.OIDC_PROVIDERS = {
        //         Azure: 0,
        //         Okta: 1,
        //         OktaWithoutAuthorizationServer: 2,
        //         Google: 3,
        //         PingOne: 4,
        //         OneLogin: 5
        //     }

        // TODO: Move to Model.cs
        public class SsoLoginInfo
        {
            [JsonPropertyName("type")]
            public int Type { get; set; }

            [JsonPropertyName("OpenIDConnectAuthority")]
            public string OpenIdConnectAuthority { get; set; }

            [JsonPropertyName("OpenIDConnectClientId")]
            public string OpenIdConnectClientId { get; set; }

            [JsonPropertyName("CompanyId")]
            public int CompanyId { get; set; }
        }

        public class OpenIdConnectConfig
        {
            [JsonPropertyName("authorization_endpoint")]
            public string AuthorizationEndpoint { get; set; }

            [JsonPropertyName("token_endpoint")]
            public string TokenEndpoint { get; set; }

            [JsonPropertyName("userinfo_endpoint")]
            public string UserInfoEndpoint { get; set; }

            [JsonPropertyName("msgraph_host")]
            public string MsGraphHost { get; set; }
        }

        public class CodeForToken
        {
            [JsonPropertyName("token_type")]
            public string TokenType { get; set; }

            [JsonPropertyName("scope")]
            public string Scope { get; set; }

            [JsonPropertyName("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonPropertyName("ext_expires_in")]
            public int ExtExpiresIn { get; set; }

            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; }

            [JsonPropertyName("refresh_token")]
            public string RefreshToken { get; set; }

            [JsonPropertyName("id_token")]
            public string IdToken { get; set; }
        }

        public class UserInfo
        {
            [JsonPropertyName("sub")]
            public string Sub { get; set; }

            [JsonPropertyName("name")]
            public string Name { get; set; }

            [JsonPropertyName("given_name")]
            public string GivenName { get; set; }

            [JsonPropertyName("picture")]
            public string Picture { get; set; }

            [JsonPropertyName("email")]
            public string Email { get; set; }
        }

        public class AzureK1Response
        {
            [JsonPropertyName("@odata.context")]
            public string OdataContext { get; set; }

            [JsonPropertyName("id")]
            public string Id { get; set; }

            [JsonPropertyName("displayName")]
            public string DisplayName { get; set; }

            [JsonPropertyName("mail")]
            public string Mail { get; set; }

            [JsonPropertyName("extensions@odata.context")]
            public string ExtensionsOdataContext { get; set; }

            [JsonPropertyName("extensions")]
            public Extension[] Extensions { get; set; }

            public class Extension
            {
                [JsonPropertyName("@odata.type")]
                public string OdataType { get; set; }

                [JsonPropertyName("extensionName")]
                public string ExtensionName { get; set; }

                [JsonPropertyName("LastPassK1")]
                public string LastPassK1 { get; set; }

                [JsonPropertyName("id")]
                public string Id { get; set; }
            }
        }

        public class AlpK2Response
        {
            [JsonPropertyName("k2")]
            public string K2 { get; set; }

            [JsonPropertyName("fragment_id")]
            public string FragmentId { get; set; }
        }

        public static async Task LoginWithSso(
            string username,
            ClientInfo clientInfo,
            IAsyncSsoUi ssoUi,
            IRestTransport transport,
            ParserOptions options,
            ISecureLogger logger, // can be null
            CancellationToken cancellationToken
        )
        {
            // We allow the logger to be null for optimization purposes
            var tagLog = options.LoggingEnabled ? new TaggedLogger("LastPass", logger ?? new NullLogger()) : null;

            var rest = new RestClient(
                transport,
                "",
                defaultHeaders: new Dictionary<string, string>
                {
                    ["User-Agent"] =
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                },
                logger: tagLog,
                useSystemJson: true
            );

            var lowerCaseUsername = username.ToLowerInvariant().Trim();
            var response = await rest.GetAsync<SsoLoginInfo>(
                    "https://lastpass.com/lmiapi/login/type?username=" + lowerCaseUsername.EncodeUri(),
                    cancellationToken
                )
                .ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var loginInfo = response.Data;
            if (loginInfo.Type <= 0)
                throw new InternalErrorException("SSO is not available for this account");

            if (loginInfo.OpenIdConnectAuthority.IsNullOrEmpty())
                throw new InternalErrorException("SSO is not available for this account");

            var response2 = await rest.GetAsync<OpenIdConnectConfig>(loginInfo.OpenIdConnectAuthority, cancellationToken).ConfigureAwait(false);
            if (!response2.IsSuccessful)
                throw MakeError(response2);

            var config = response2.Data;

            var redirectUri = "https://accounts.lastpass.com/federated/oidcredirect.html";
            var state = Crypto.RandomHex(32);
            var codeVerifier = Crypto.RandomHex(96);
            var codeChallenge = Crypto.Sha256(codeVerifier).ToUrlSafeBase64NoPadding();
            var nonce = Crypto.RandomHex(16);

            var urlParams = new Dictionary<string, string>
            {
                ["client_id"] = loginInfo.OpenIdConnectClientId,
                ["redirect_uri"] = redirectUri,
                ["response_type"] = "code",
                ["scope"] = "openid email profile",
                ["state"] = state,
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256",
                ["response_mode"] = "fragment",
                ["login_hint"] = lowerCaseUsername,
                ["nonce"] = nonce,
            };
            var url = config.AuthorizationEndpoint + "?" + string.Join("&", urlParams.Select(kv => kv.Key + "=" + kv.Value.EncodeUri()));

            var redirectedTo = await ssoUi.PerformSsoLogin(url, redirectUri, cancellationToken).ConfigureAwait(false);
            if (redirectedTo.IsNullOrEmpty())
                throw new InternalErrorException("SSO login failed: no redirect"); // TOOD: Add a new exception type

            var code = Url.ExtractQueryParameter(redirectedTo, "code");
            if (code.IsNullOrEmpty())
                throw new InternalErrorException("SSO login failed: no code"); // TOOD: Add a new exception type

            var responseState = Url.ExtractQueryParameter(redirectedTo, "state");
            if (responseState.IsNullOrEmpty())
                throw new InternalErrorException("SSO login failed: no state"); // TOOD: Add a new exception type

            // Verify the code
            if (state != responseState)
                throw new InternalErrorException("SSO login failed: invalid state"); // TOOD: Add a new exception type

            // Exchange the code for a token
            var tokenResponse = await rest.PostFormAsync<CodeForToken>(
                    config.TokenEndpoint,
                    new Dictionary<string, object>
                    {
                        ["client_id"] = loginInfo.OpenIdConnectClientId,
                        ["code"] = code,
                        ["redirect_uri"] = redirectUri,
                        ["code_verifier"] = codeVerifier,
                        ["grant_type"] = "authorization_code",
                    },
                    headers: new Dictionary<string, string> { ["Origin"] = "chrome-extension://hdokiejnpimakedhajhdlcegeplioahd" },
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (!tokenResponse.IsSuccessful)
                throw MakeError(tokenResponse);

            var token = tokenResponse.Data;

            // Validate and parse JWT token

            var idOpenId = token.Scope.Split(' ').Contains("openid");
            if (!idOpenId)
                throw new InternalErrorException("SSO login failed: missing openid scope"); // TOOD: Add a new exception type

            // After filterProtocolClaims:
            // {
            //     "email": "dmitry@downhillpro.xyz",
            //     "name": "Dmitry",
            //     "oid": "cb151fd4-0560-406d-847f-915f3598b052",
            //     "preferred_username": "dmitry@downhillpro.xyz",
            //     "rh": "1.ASgAwV5aTMWaEkabTGvtF4u2WmtUpVF2dvNIr8-MFblMzcIoAOooAA.",
            //     "sid": "001368d9-abd4-0956-0e0c-ee9a269b511d",
            //     "sub": "d1FosjQTGSYp2_PIS2TsIx4C3rcmTxMFDFTNmMEBDYo",
            //     "tid": "4c5a5ec1-9ac5-4612-9b4c-6bed178bb65a",
            //     "uti": "kGicXBjTeECT26jCXGwSAQ",
            //     "ver": "2.0"
            // }

            // The following properties are stripped:
            // [
            //     "nonce",
            //     "at_hash",
            //     "iat",
            //     "nbf",
            //     "exp",
            //     "aud",
            //     "iss",
            //     "c_hash"
            // ]

            // Get the user claims:

            var azureGraphApiHost = config.AuthorizationEndpoint.Contains("microsoftonline.us") ? "graph.microsoft.us" : "graph.microsoft.com";

            var userInfoResponse = await rest.GetAsync<UserInfo>(
                    $"https://{azureGraphApiHost}/oidc/userinfo",
                    headers: new Dictionary<string, string> { ["Authorization"] = $"Bearer {token.AccessToken}" },
                    cancellationToken
                )
                .ConfigureAwait(false);
            if (!userInfoResponse.IsSuccessful)
                throw MakeError(userInfoResponse);

            var userInfo = userInfoResponse.Data;

            // TODO: Merge claims

            // Check that all the lowercased emails are the same:
            //   1. The email given by the user
            //   2. The email from JWT
            //   3. The preferred_username from JWT

            // Fetch K1 (this is only for Azure)
            var k1Response = await rest.GetAsync<AzureK1Response>(
                    $"https://{azureGraphApiHost}/v1.0/me?$select=id,displayName,mail&$expand=extensions",
                    headers: new Dictionary<string, string> { ["Authorization"] = $"Bearer {token.AccessToken}" },
                    cancellationToken
                )
                .ConfigureAwait(false);
            if (!k1Response.IsSuccessful)
                throw MakeError(k1Response);

            var k1 = k1Response.Data.Extensions.FirstOrDefault(x => x.Id == "com.lastpass.keys")?.LastPassK1;

            // Get K2 from ALP server
            var alpResponse = await rest.PostJsonAsync<AlpK2Response>(
                    "https://accounts.lastpass.com/federatedlogin/api/v1/getkey",
                    new Dictionary<string, object> { ["company_id"] = loginInfo.CompanyId, ["id_token"] = token.IdToken },
                    headers: new Dictionary<string, string>
                    {
                        ["Origin"] = "chrome-extension://hdokiejnpimakedhajhdlcegeplioahd",
                        ["User-Agent"] =
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                    },
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (!alpResponse.IsSuccessful)
                throw MakeError(alpResponse);

            var k2 = alpResponse.Data.K2;
            var fragmentId = alpResponse.Data.FragmentId;

            var k1Bytes = k1.Decode64Loose();
            var k2Bytes = k2.Decode64Loose();

            // xor k1 and k2
            var k1XorK2 = new byte[k1Bytes.Length];
            for (int i = 0; i < k1Bytes.Length; i++)
                k1XorK2[i] = (byte)(k1Bytes[i] ^ k2Bytes[i]);

            var k1Sha256 = Crypto.Sha256(k1Bytes);
            var k1XorK2Sha256 = Crypto.Sha256(k1XorK2);

            var calculatedFragmentId = k1Sha256.ToBase64();

            // Derive the key

            var iterationCount = 600_000; // TODO: !!!
            var password = k1XorK2Sha256.ToBase64();
            //var key = Util.DeriveKey(lowerCaseUsername, password, iterationCount);
            //var keyHash = Util.DeriveKeyHash(lowerCaseUsername, password, iterationCount).ToHex();

            var loginResponseXml = await PerformSingleLoginRequest(
                    lowerCaseUsername,
                    password,
                    iterationCount,
                    MfaMethod.None,
                    false,
                    new Dictionary<string, object>
                    {
                        ["xml"] = "1", // TODO: Do we need this?
                        ["method"] = "web", // TODO: Do we need this?
                        ["authsessionid"] = "",
                        ["alpfragmentid"] = alpResponse.Data.FragmentId,
                        ["calculatedfragmentid"] = calculatedFragmentId,
                    },
                    clientInfo,
                    rest,
                    cancellationToken
                )
                .ConfigureAwait(false);

            // loginResponse = await rest.PostFormAsync(
            //         "https://lastpass.com/login.php",
            //         new Dictionary<string, object>
            //         {
            //             ["hash"] = keyHash,
            //             ["xml"] = "1",
            //             ["method"] = "web",
            //             ["username"] = lowerCaseUsername,
            //             //["encrypted_username"] = "LX/IONwUbfzIcgU45khH84LXFIPtJLr3Nr7TEH9nHD0=",
            //             ["iterations"] = iterationCount,
            //             //["email"] = lowerCaseUsername,
            //             ["outofbandsupported"] = "1",
            //             ["uuid"] = "ba8082fd21cd6a76d23767bc0f7274c2de845baa960f010e95e4d5d2a6e7b16",
            //             //["deviceId"] = "",
            //             //["key_integrity_fingerprint"] = "c7820132bc98174321f2f1c337ec9df71de4f3eca6a6b5b6f896739b2c708fb0",
            //             ["authsessionid"] = "",
            //             ["alpfragmentid"] = alpResponse.Data.FragmentId,
            //             ["calculatedfragmentid"] = calculatedFragmentId,
            //             ["sesameotp"] = "",
            //             ["otp"] = "",
            //             ["lcid"] = "",
            //             ["domain"] = "",
            //             //["lostpwotphash"] = "2c577da2aca1bfc6feb411ff3dac0fe7ec77d67c292720f705654492592491a1",
            //         },
            //         cancellationToken
            //     )
            //     .ConfigureAwait(false);

            // if (!loginResponse.IsSuccessful)
            //     throw MakeError(loginResponse);

            var session = ExtractSessionFromLoginResponse(loginResponseXml, iterationCount, clientInfo);
            if (session == null)
                throw new InternalErrorException("Login failed");
        }

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

            var changedIterationCount = false;
            var changedServer = false;
            var forceMfaMethod = MfaMethod.None;

            while (true)
            {
                // 2. Knowing the iterations count we can hash the password and log in.
                //    On the first attempt simply with the username and password.
                var response = await PerformSingleLoginRequest(
                        username,
                        password,
                        keyIterationCount,
                        forceMfaMethod,
                        false,
                        [],
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();

                var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
                if (session != null)
                    return (session, rest);

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
                        return (s, rest);
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
            string password,
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
                ["hash"] = Util.DeriveKeyHash(username, password, keyIterationCount).ToHex(),
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
                    case Cancelled:
                        throw new CanceledMultiFactorException("Second factor step is canceled by the user");
                }

                // User provided a passcode
                var otp = otpResult.AsT0;

                var response = await PerformSingleLoginRequest(
                        username,
                        password,
                        keyIterationCount,
                        method,
                        otp.RememberMe,
                        new Dictionary<string, object> { ["otp"] = otp.Passcode },
                        clientInfo,
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                var session = ExtractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
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
            string password,
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
                        password,
                        keyIterationCount,
                        method,
                        rememberMe,
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

        // TODO: Log unsupported methods, don't just ignore them
        internal static MfaMethod[] ParseAvailableMfaMethods(XDocument response)
        {
            return (GetOptionalErrorAttribute(response, "enabled_providers") ?? "")
                .Split(',')
                .Select(x => KnownMfaMethods.GetValueOrDefault(x, MfaMethod.None))
                .Where(x => x != MfaMethod.None)
                .ToArray();
        }

        internal static Session ExtractSessionFromLoginResponse(XDocument response, int keyIterationCount, ClientInfo clientInfo)
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
