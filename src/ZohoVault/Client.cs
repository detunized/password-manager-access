// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault.Ui;
using R = PasswordManagerAccess.ZohoVault.Response;

namespace PasswordManagerAccess.ZohoVault
{
    using HttpCookies = Dictionary<string, string>;
    using HttpHeaders = Dictionary<string, string>;
    using PostParameters = Dictionary<string, object>;

    public static class Client
    {
        //
        // Public API
        //

        //
        // Single shot
        //

        public static Vault Open(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return Open(credentials, settings, ui, storage, transport);
        }

        //
        // LogIn, DownloadVault, LogOut sequence
        //

        public static Session LogIn(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage)
        {
            var transport = new RestTransport();
            try
            {
                return LogIn(credentials, settings, ui, storage, transport);
            }
            catch (Exception)
            {
                transport.Dispose();
                throw;
            }
        }

        public static Vault DownloadVault(Session session, string passphrase)
        {
            var authInfo = RequestAuthInfo(session.Cookies, session.UserInfo.Domain, session.Rest);
            var vaultKey = DeriveAndVerifyVaultKey(passphrase, authInfo);
            var vaultResponse = FetchVault(session.Cookies, session.UserInfo.Domain, session.Rest);
            var sharingKey = DecryptSharingKey(vaultResponse, vaultKey);
            var accounts = ParseAccounts(vaultResponse, vaultKey, sharingKey);

            return new Vault(accounts);
        }

        public static void LogOut(Session session)
        {
            try
            {
                if (session.Settings.KeepSession)
                    return;

                EraseCookies(session.Storage);
                LogOut(session.Cookies, session.UserInfo.Domain, session.Rest);
            }
            finally
            {
                session.Transport.Dispose();
            }
        }

        //
        // Internal
        //

        internal static Vault Open(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            var session = LogIn(credentials, settings, ui, storage, transport);
            try
            {
                var vault = DownloadVault(session, credentials.Passphrase);
                return vault;
            }
            finally
            {
                LogOut(session);
            }
        }

        internal static Session LogIn(Credentials credentials, Settings settings, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            var rest = new RestClient(transport, defaultHeaders: Headers);

            // This token is needed to access other pages of the login flow. It's sent via headers,
            // cookies and in the request data.
            var token = RequestToken(rest);

            // Each user is associated with a specific region. We get this in a form of a sign-in URL.
            var userInfo = RequestUserInfo(credentials.Username, token, DefaultDomain, rest);

            bool needLogin;
            if (TryDeserializeJson<HttpCookies>(storage.LoadString(Cookies), out var cookies))
            {
                // We have the cookies from the previous session. We can try to use them to skip the login.
                needLogin = false;

                // The CSR token is stored in the cookies.
                cookies["iamcsr"] = token;
            }
            else
            {
                needLogin = true;
            }

            // Normally we allow two attempts. The first one to "test" the old cookies and the second one to log in and perform the download.
            // In case we don't have any cookies stored, we only allow one attempt to log in and perform the download.
            var maxAttempts = needLogin ? 1 : 2;

            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                if (needLogin)
                {
                    // Perform the login dance that possibly involves the MFA steps. The cookies are later used by the subsequent requests.
                    cookies = LogIn(userInfo, credentials.Password, token, ui, storage, rest);

                    // Save the cookies for the next time
                    if (settings.KeepSession)
                        SaveCookies(cookies, storage);
                }

                try
                {
                    // Test if the session is valid by making a simple request
                    RequestAuthInfo(cookies, userInfo.Domain, rest);

                    // If we get here, the session is valid
                    return new Session(cookies, token, userInfo, rest, transport, settings, storage);
                }
                catch (InvalidTicketException)
                {
                    // If the cookies have expired, we need to do a full login
                    EraseCookies(storage);
                    needLogin = true;
                }
            }

            throw new InternalErrorException("Logical error");
        }

        //
        // Internal
        //

        // Use https://accounts.zoho.eu/oauth/serverinfo to find all domains
        internal static string UrlToDomain(string url)
        {
            const string hostPrefix = "accounts.";

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !uri.Host.StartsWith(hostPrefix))
                throw new InternalErrorException($"Expected a valid URL with a domain starting with '{hostPrefix}', got '{url}'");

            // Everywhere in the code we use the main domain name, like zoho.com or zohocloud.ca.
            return uri.Host.Substring(hostPrefix.Length);
        }

        internal static string RequestToken(RestClient rest)
        {
            var loginPage = rest.Get(LoginPageUrl);
            if (!loginPage.IsSuccessful)
                throw MakeErrorOnFailedRequest(loginPage);

            var token = loginPage.Cookies.GetOrDefault("iamcsr", "");
            if (token.IsNullOrEmpty())
                throw MakeInvalidResponseError("'iamcsr' cookie is not set by the server");

            return token;
        }

        internal class UserInfo
        {
            public string Id { get; }
            public string Digest { get; }
            public string Domain { get; }

            public UserInfo(string id, string digest, string domain)
            {
                Id = id;
                Digest = digest;
                Domain = domain;
            }
        }

        internal static UserInfo RequestUserInfo(string username, string token, string domain, RestClient rest)
        {
            var response = rest.PostForm<R.Lookup>(
                LookupUrl(domain, username),
                new PostParameters
                {
                    ["mode"] = "primary",
                    ["cli_time"] = Os.UnixMilliseconds(),
                    ["servicename"] = ServiceName,
                },
                headers: new HttpHeaders { ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}" },
                cookies: new HttpCookies { ["iamcsr"] = token }
            );

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;

            // Success (200..299)
            if (status.StatusCode / 100 == 2)
            {
                var result = status.Result;
                if (result == null)
                    throw MakeInvalidResponseError("lookup result not found");

                return new UserInfo(result.UserId, result.Digest, UrlToDomain(result.Href));
            }

            var error = GetError(status);
            switch (error.Code)
            {
                // User exists in another data center
                case "U400":
                    var redirect = status.Redirect;
                    if (redirect == null)
                        throw MakeInvalidResponseError("redirect info not found");

                    return RequestUserInfo(username, token, UrlToDomain(redirect.RedirectUrl), rest);

                // User doesn't exist
                case "U401":
                    throw new BadCredentialsException("The username is invalid");
            }

            throw MakeInvalidResponseError(status);
        }

        internal static HttpCookies LogIn(UserInfo userInfo, string password, string token, IUi ui, ISecureStorage storage, RestClient rest)
        {
            var cookies = new HttpCookies { ["iamcsr"] = token };

            // Check if we have a "remember me" token saved from one of the previous sessions
            var (rememberMeKey, rememberMeValue) = LoadRememberMeToken(storage);
            var haveRememberMe = !rememberMeKey.IsNullOrEmpty() && !rememberMeValue.IsNullOrEmpty();
            if (haveRememberMe)
                cookies[rememberMeKey] = rememberMeValue;

            var response = rest.PostJson<R.LogIn>(
                LogInUrl(userInfo, Os.UnixMilliseconds()),
                parameters: new PostParameters { ["passwordauth"] = new Dictionary<string, string> { ["password"] = password } },
                headers: new HttpHeaders { ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}" },
                cookies: cookies
            );

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;
            if (status.StatusCode / 100 == 2)
            {
                // Successfully logged in
                if (SuccessErrorCodes.Contains(status.Code))
                    return response.Cookies;

                // MFA required
                if (status.Code == "MFA302")
                    return LogInMfa(userInfo, status.Result, token, ui, storage, rest);

                throw MakeInvalidResponseError(status);
            }

            var error = GetError(status);
            switch (error.Code)
            {
                // Bad password
                case "IN102":
                    throw new BadCredentialsException("The password is incorrect");
                // Captcha
                case "IN107":
                case "IN108":
                    throw new UnsupportedFeatureException("Captcha is not supported");
            }

            // Some other error
            throw MakeInvalidResponseError(status);
        }

        internal static HttpCookies LogInMfa(
            UserInfo userInfo,
            R.LogInResult logInResult,
            string token,
            IUi ui,
            ISecureStorage storage,
            RestClient rest
        )
        {
            void CheckCancel(Passcode passcode)
            {
                if (passcode == Passcode.Cancel)
                    throw new CanceledMultiFactorException("Second factor step is canceled by the user");
            }

            var methods = logInResult.MfaMethods?.AllowedMethods;
            if (methods == null)
                throw MakeInvalidResponseError("allowed MFA methods not found");

            Passcode code;

            if (methods.Contains("totp"))
            {
                code = ui.ProvideGoogleAuthPasscode();
                CheckCancel(code);
                SubmitTotp(userInfo, code, token, logInResult.MfaToken, rest);
            }
            else if (methods.Contains("yubikey"))
            {
                throw new UnsupportedFeatureException("Zoho removed support for the classic YubiKey. FIDO U2F is not supported yet.");
            }
            else
            {
                var unsupportedMethods = methods.JoinToString(", ");
                throw new UnsupportedFeatureException($"MFA methods '{unsupportedMethods}' are not supported");
            }

            // Has to be done regardless of the "remember me" setting
            var cookies = MarkDeviceTrusted(userInfo, code.RememberMe, token, logInResult.MfaToken, rest);

            if (code.RememberMe)
                FindAndSaveRememberMeToken(cookies, storage);
            else
                EraseRememberMeToken(storage);

            return cookies;
        }

        internal static void SubmitTotp(UserInfo userInfo, Passcode passcode, string token, string mfaToken, RestClient rest)
        {
            var response = rest.PostJson<R.Totp>(
                TotpUrl(userInfo, Os.UnixMilliseconds()),
                parameters: new PostParameters { ["totpsecauth"] = new Dictionary<string, string> { ["code"] = passcode.Code } },
                headers: new HttpHeaders { ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}", ["Z-Authorization"] = $"Zoho-ticket {mfaToken}" },
                cookies: new HttpCookies { ["iamcsr"] = token }
            );

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;

            // Success (200..299)
            if (status.StatusCode / 100 == 2 && status.Result.Status == "success")
                return;

            var error = GetError(status);
            if (error.Code == "IN105")
                throw new BadMultiFactorException("MFA code is incorrect");

            throw MakeInvalidResponseError(status);
        }

        internal static HttpCookies MarkDeviceTrusted(UserInfo userInfo, bool trust, string token, string mfaToken, RestClient rest)
        {
            var response = rest.PostJson<R.TrustMfa>(
                TrustUrl(userInfo),
                new PostParameters { ["trustmfa"] = new Dictionary<string, object> { ["trust"] = trust } },
                headers: new HttpHeaders { ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}", ["Z-Authorization"] = $"Zoho-ticket {mfaToken}" },
                cookies: new HttpCookies { ["iamcsr"] = token }
            );

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;
            if (status.StatusCode / 100 == 2 && SuccessErrorCodes.Contains(status.Code))
                return response.Cookies;

            throw MakeInvalidResponseError(status);
        }

        internal static void LogOut(HttpCookies cookies, string domain, RestClient rest)
        {
            // It's ok to have 2XX or 3XX HTTP status. Sometimes the server sends a redirect.
            // There's no need to follow it to complete a logout.
            var response = rest.Get(LogoutUrl(domain), cookies: cookies, maxRedirects: 0);
            if (response.HasError || (int)response.StatusCode / 100 > 3)
                throw MakeErrorOnFailedRequest(response);
        }

        internal readonly struct AuthInfo
        {
            public readonly int IterationCount;
            public readonly byte[] Salt;
            public readonly byte[] EncryptionCheck;

            public AuthInfo(int iterationCount, byte[] salt, byte[] encryptionCheck)
            {
                IterationCount = iterationCount;
                Salt = salt;
                EncryptionCheck = encryptionCheck;
            }
        }

        internal static AuthInfo RequestAuthInfo(HttpCookies cookies, string domain, RestClient rest)
        {
            var info = GetWrapped<R.AuthInfo>(AuthInfoUrl(domain), cookies, rest);

            if (info.KdfMethod != "PBKDF2_AES")
                throw new UnsupportedFeatureException($"KDF method '{info.KdfMethod}' is not supported");

            return new AuthInfo(info.Iterations, info.Salt.ToBytes(), info.Passphrase.Decode64());
        }

        internal static R.Vault FetchVault(HttpCookies cookies, string domain, RestClient rest) =>
            GetWrapped<R.Vault>(VaultUrl(domain), cookies, rest);

        internal static byte[] DeriveAndVerifyVaultKey(string passphrase, AuthInfo authInfo)
        {
            // Decryption key
            var key = Util.ComputeKey(passphrase, authInfo.Salt, authInfo.IterationCount);

            // Verify that the key is correct
            // AuthInfo.EncryptionCheck contains some encrypted JSON that could be
            // decrypted and parsed to check if the passphrase is correct. We have
            // to rely here on the encrypted JSON simply not parsing correctly and
            // producing some sort of error.
            var decrypted = Util.Decrypt(authInfo.EncryptionCheck, key).ToUtf8(); // TODO: See if ToUtf8 could throw something

            JToken parsed = null;
            try
            {
                parsed = JToken.Parse(decrypted);
            }
            catch (JsonException) { }

            // This would be null in case of JSON exception or if Parse returned null (would it?)
            if (parsed == null)
                throw new BadCredentialsException("Passphrase is incorrect");

            return key;
        }

        internal static byte[] DecryptSharingKey(R.Vault vaultResponse, byte[] key)
        {
            if (vaultResponse.PrivateKey.IsNullOrEmpty() || vaultResponse.SharingKey.IsNullOrEmpty())
                return null;

            var privateKeyComponents = Util.Decrypt(vaultResponse.PrivateKey.Decode64(), key).ToUtf8().Split(',');
            if (privateKeyComponents.Length != 8)
                throw new InternalErrorException("Invalid RSA key format");

            var rsaKey = new RSAParameters
            {
                Modulus = privateKeyComponents[0].DecodeHexLoose(),
                Exponent = privateKeyComponents[1].ToBigInt().ToByteArray(),
                D = privateKeyComponents[2].DecodeHexLoose(),
                P = privateKeyComponents[3].DecodeHexLoose(),
                Q = privateKeyComponents[4].DecodeHexLoose(),
                DP = privateKeyComponents[5].DecodeHexLoose(),
                DQ = privateKeyComponents[6].DecodeHexLoose(),
                InverseQ = privateKeyComponents[7].DecodeHexLoose(),
            };

            return Crypto.DecryptRsaPkcs1(vaultResponse.SharingKey.DecodeHex(), rsaKey);
        }

        internal static Account[] ParseAccounts(R.Vault vaultResponse, byte[] vaultKey, byte[] sharingKey)
        {
            // TODO: Test on non account type secrets!
            // TODO: Test on accounts with missing fields!
            return vaultResponse.Secrets.Select(x => ParseAccount(x, x.IsShared == "YES" ? sharingKey : vaultKey)).Where(x => x != null).ToArray();
        }

        // Returns null on accounts that don't parse
        internal static Account ParseAccount(R.Secret secret, byte[] key)
        {
            try
            {
                var data = JsonConvert.DeserializeObject<R.SecretData>(secret.Data ?? "{}");
                return new Account(
                    secret.Id,
                    secret.Name ?? "",
                    Util.DecryptStringLoose(data.Username, key),
                    Util.DecryptStringLoose(data.Password, key),
                    secret.Url ?? "",
                    Util.DecryptStringLoose(secret.Note, key)
                );
            }
            catch (JsonException)
            {
                // If it doesn't parse then it's some other kind of unsupported secret type. Ignore.
                return null;
            }
        }

        internal static T GetWrapped<T>(string url, HttpCookies cookies, RestClient rest)
        {
            // GET
            var response = rest.Get<R.ResponseEnvelope<T>>(url, cookies: cookies);
            if (!IsSuccessful(response))
                throw MakeErrorOnFailedRequest(response);

            return response.Data.Payload;
        }

        internal static R.StatusError GetError(R.Status status)
        {
            if (status.Errors == null || status.Errors.Length == 0)
                throw MakeInvalidResponseError(
                    $"request failed with code '{status.StatusCode}/{status.Code}' and message '{status.Message}' but error wasn't provided"
                );

            return status.Errors[0];
        }

        internal static void FindAndSaveRememberMeToken(HttpCookies cookies, ISecureStorage storage)
        {
            var name = cookies.Keys.FirstOrDefault(x => RememberMeCookieNamePattern.IsMatch(x));
            if (name.IsNullOrEmpty())
                return;

            SaveRememberMeToken(name, cookies[name!], storage);
        }

        internal static bool TryDeserializeJson<T>(string json, out T result)
        {
            try
            {
                result = JsonConvert.DeserializeObject<T>(json ?? "");
                return result != null;
            }
            catch (JsonException)
            {
                result = default;
                return false;
            }
        }

        //
        // Private
        //

        private class InvalidTicketException : BaseException
        {
            public InvalidTicketException(string operation)
                : base($"Operation '{operation}' failed", null) { }
        }

        private static bool IsSuccessful<T>(RestResponse<string, R.ResponseEnvelope<T>> response)
        {
            return response.IsSuccessful && response.Data?.Operation?.Result?.Status == "success";
        }

        private static BaseException MakeErrorOnFailedRequest(RestResponse response)
        {
            if (response.IsNetworkError)
                return NetworkErrorError(response);

            return new InternalErrorException($"Request to {response.RequestUri} failed with HTTP status {(int)response.StatusCode}", response.Error);
        }

        private static BaseException MakeErrorOnFailedRequest<T>(RestResponse<string, R.ResponseEnvelope<T>> response)
        {
            if (response.IsNetworkError)
                return NetworkErrorError(response);

            var operation = response.Data.Operation;
            var result = operation.Result;

            // This happens when the login cookies have expired.
            if (result is { Status: "failed", ErrorCode: "INVALID_TICKET" or "Z223" })
                return new InvalidTicketException(operation.Name);

            return new InternalErrorException(
                $"Operation '{operation.Name}' failed with status '{result.Status}', error code '{result.ErrorCode}' and message '{result.Message}'"
            );
        }

        private static InternalErrorException MakeInvalidResponseError(string message, Exception original = null)
        {
            return new InternalErrorException($"Unexpected response: {message}", original);
        }

        private static InternalErrorException MakeInvalidResponseError(R.Status status)
        {
            var message = $"message: '{status.Message}', status code: '{status.StatusCode}/{status.Code}'";
            if (status.Errors?.Length > 0)
            {
                var error = GetError(status);
                message += $", error code: '{error.Code}'error message: '{error.Message}'";
            }

            return MakeInvalidResponseError(message);
        }

        private static NetworkErrorException NetworkErrorError(RestResponse response)
        {
            return new NetworkErrorException($"Request to {response.RequestUri} failed with a network error", response.Error);
        }

        private static (string key, string value) LoadRememberMeToken(ISecureStorage storage)
        {
            return (storage.LoadString(RememberMeTokenKey), storage.LoadString(RememberMeTokenValue));
        }

        private static void SaveRememberMeToken(string key, string value, ISecureStorage storage)
        {
            storage.StoreString(RememberMeTokenKey, key);
            storage.StoreString(RememberMeTokenValue, value);
        }

        private static void EraseRememberMeToken(ISecureStorage storage)
        {
            SaveRememberMeToken(null, null, storage);
        }

        private static void SaveCookies(HttpCookies cookies, ISecureStorage storage)
        {
            storage.StoreString(Cookies, JsonConvert.SerializeObject(cookies));
        }

        private static void EraseCookies(ISecureStorage storage)
        {
            storage.StoreString(Cookies, null);
        }

        //
        // Data
        //

        private const string DefaultDomain = "zoho.com";

        private const string ServiceName = "ZohoVault";
        private const string OAuthScope = "ZohoVault.secrets.READ";

        private static readonly string LoginPageUrl = $"https://accounts.zoho.com/oauth/v2/auth?response_type=code&scope={OAuthScope}&prompt=consent";

        private static string LookupUrl(string domain, string username) => $"https://accounts.{domain}/signin/v2/lookup/{username}";

        private static string LogInUrl(UserInfo user, long timestamp) =>
            $"https://accounts.{user.Domain}/signin/v2/primary/{user.Id}/password?digest={user.Digest}&cli_time={timestamp}&servicename={ServiceName}";

        private static string TotpUrl(UserInfo user, long timestamp) =>
            $"https://accounts.{user.Domain}/signin/v2/secondary/{user.Id}/totp?digest={user.Digest}&cli_time={timestamp}&servicename={ServiceName}";

        private static string TrustUrl(UserInfo user) => $"https://accounts.{user.Domain}/signin/v2/secondary/{user.Id}/trust";

        private static string AuthInfoUrl(string domain) => $"https://vault.{domain}/api/json/login?OPERATION_NAME=GET_LOGIN";

        private static string VaultUrl(string domain) => $"https://vault.{domain}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=-1";

        private static string LogoutUrl(string domain) => $"https://accounts.{domain}/logout?servicename=ZohoVault";

        private const string UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";

        private static readonly string[] SuccessErrorCodes = { "SI200", "SI300", "SI301", "SI302", "SI303", "SI304" };

        // Important! Most of the requests fail without a valid User-Agent header
        private static readonly Dictionary<string, string> Headers = new() { { "User-Agent", UserAgent } };

        private static readonly Regex RememberMeCookieNamePattern = new(@"^IAM.*TFATICKET_\d+$");

        private const string RememberMeTokenKey = "remember-me-token-key";
        private const string RememberMeTokenValue = "remember-me-token-value";
        private const string Cookies = "cookies";
    }
}
