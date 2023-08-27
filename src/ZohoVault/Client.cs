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

    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string password,
                                          string passphrase,
                                          IUi ui,
                                          ISecureStorage storage,
                                          IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // This token is needed to access other pages of the login flow. It's sent via headers,
            // cookies and in the request data.
            var token = RequestToken(rest);

            // TLD is determined by the region/data center. Each user is associated with a specific region.
            var userInfo = RequestUserInfo(username, token, DataCenterToTld(DefaultDataCenter), rest);

            // Perform the login dance that possibly involves the MFA steps. The cookies are later
            // used by the subsequent requests.
            //
            // TODO: It would be ideal to figure out which cookies are needed for general
            // cleanliness. It was too many of them and so they are now passed altogether a bundle
            // between the requests.
            var cookies = LogIn(userInfo, password, token, ui, storage, rest);

            try
            {
                var vaultKey = Authenticate(passphrase, cookies, userInfo.Tld, rest);
                var vaultResponse = DownloadVault(cookies, userInfo.Tld, rest);
                var sharingKey = DecryptSharingKey(vaultResponse, vaultKey);

                return ParseAccounts(vaultResponse, vaultKey, sharingKey);
            }
            finally
            {
                LogOut(cookies, userInfo.Tld, rest);
            }
        }

        //
        // Internal
        //

        internal static string DataCenterToTld(string dataCenter)
        {
            // From here: https://accounts.zoho.eu/oauth/serverinfo
            switch (dataCenter)
            {
            case "us":
                return "com";
            case "eu":
                return "eu";
            case "in":
                return "in";
            case "au":
                return "com.au";
            }

            throw new UnsupportedFeatureException($"Unsupported data center '{dataCenter}'");
        }

        internal static string RequestToken(RestClient rest)
        {
            var loginPage = rest.Get(LoginPageUrl, Headers);
            if (!loginPage.IsSuccessful)
                throw MakeErrorOnFailedRequest(loginPage);

            var token = loginPage.Cookies.GetOrDefault("iamcsr", "");
            if (token.IsNullOrEmpty())
                throw MakeInvalidResponseError("'iamcsr' cookie is not set by the server");

            return token;
        }

        internal readonly ref struct UserInfo
        {
            public readonly string Id;
            public readonly string Digest;
            public readonly string Tld;

            public UserInfo(string id, string digest, string tld)
            {
                Id = id;
                Digest = digest;
                Tld = tld;
            }
        }

        internal static UserInfo RequestUserInfo(string username, string token, string tld, RestClient rest)
        {
            var response = rest.PostForm<R.Lookup>(
                LookupUrl(tld, username),
                new Dictionary<string, object>
                {
                    ["mode"] = "primary",
                    ["cli_time"] = Os.UnixMilliseconds(),
                    ["servicename"] = ServiceName,
                },
                headers: new Dictionary<string, string> {["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}"},
                cookies: new Dictionary<string, string> {["iamcsr"] = token});

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;

            // Success (200..299)
            if (status.StatusCode / 100 == 2)
            {
                var result = status.Result;
                if (result == null)
                    throw MakeInvalidResponseError("lookup result not found");

                return new UserInfo(id: result.UserId,
                                    digest: result.Digest,
                                    tld: DataCenterToTld(result.DataCenter));
            }

            var error = GetError(status);
            switch (error.Code)
            {
            // User exists in another data center
            case "U400":
                var redirect = status.Redirect;
                if (redirect == null)
                    throw MakeInvalidResponseError("redirect info not found");

                return RequestUserInfo(username, token, DataCenterToTld(redirect.DataCenter), rest);
            // User doesn't exist
            case "U401":
                throw new BadCredentialsException("The username is invalid");
            }

            throw MakeInvalidResponseError(status);
        }

        internal static HttpCookies LogIn(UserInfo userInfo,
                                          string password,
                                          string token,
                                          IUi ui,
                                          ISecureStorage storage,
                                          RestClient rest)
        {
            var cookies = new Dictionary<string, string> {["iamcsr"] = token};

            // Check if we have a "remember me" token saved from one of the previous sessions
            var (rememberMeKey, rememberMeValue) = LoadRememberMeToken(storage);
            bool haveRememberMe = !rememberMeKey.IsNullOrEmpty() && !rememberMeValue.IsNullOrEmpty();
            if (haveRememberMe)
                cookies[rememberMeKey] = rememberMeValue;

            var response = rest.PostJson<R.LogIn>(LogInUrl(userInfo, Os.UnixMilliseconds()),
                                                  parameters: new Dictionary<string, object>
                                                  {
                                                      ["passwordauth"] = new Dictionary<string, string>
                                                      {
                                                          ["password"] = password
                                                      },
                                                  },
                                                  headers: new Dictionary<string, string>
                                                  {
                                                      ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}"
                                                  },
                                                  cookies: cookies);

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

        internal static HttpCookies LogInMfa(UserInfo userInfo,
                                             R.LogInResult logInResult,
                                             string token,
                                             IUi ui,
                                             ISecureStorage storage,
                                             RestClient rest)
        {
            void CheckCancel(Ui.Passcode passcode)
            {
                if (passcode == Ui.Passcode.Cancel)
                    throw new CanceledMultiFactorException("Second factor step is canceled by the user");
            }

            var methods = logInResult.MfaMethods?.AllowedMethods;
            if (methods == null)
                throw MakeInvalidResponseError("allowed MFA methods not found");

            Ui.Passcode code;

            if (methods.Contains("totp"))
            {
                code = ui.ProvideGoogleAuthPasscode();
                CheckCancel(code);
                SubmitTotp(userInfo, code, token, logInResult.MfaToken, rest);
            }
            else if (methods.Contains("yubikey"))
            {
                throw new UnsupportedFeatureException(
                    $"Zoho removed support for the classic YubiKey. FIDO U2F is not supported yet.");
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

        internal static void SubmitTotp(UserInfo userInfo, Ui.Passcode passcode, string token, string mfaToken, RestClient rest)
        {
            var response = rest.PostJson<R.Totp>(TotpUrl(userInfo, Os.UnixMilliseconds()),
                                                 parameters: new Dictionary<string, object>
                                                 {
                                                     ["totpsecauth"] = new Dictionary<string, string>
                                                     {
                                                         ["code"] = passcode.Code,
                                                     },
                                                 },
                                                 headers: new Dictionary<string, string>
                                                 {
                                                     ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}",
                                                     ["Z-Authorization"] = $"Zoho-ticket {mfaToken}",
                                                 },
                                                 cookies: new Dictionary<string, string>
                                                 {
                                                     ["iamcsr"] = token
                                                 });

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

        internal static HttpCookies MarkDeviceTrusted(UserInfo userInfo,
                                                      bool trust,
                                                      string token,
                                                      string mfaToken,
                                                      RestClient rest)
        {
            var response = rest.PostJson<R.TrustMfa>(TrustUrl(userInfo),
                                                     new Dictionary<string, object>
                                                     {
                                                         ["trustmfa"] = new Dictionary<string, object>
                                                         {
                                                             ["trust"] = trust
                                                         },
                                                     },
                                                     headers: new Dictionary<string, string>
                                                     {
                                                         ["X-ZCSRF-TOKEN"] = $"iamcsrcoo={token}",
                                                         ["Z-Authorization"] = $"Zoho-ticket {mfaToken}",
                                                     },
                                                     cookies: new Dictionary<string, string>
                                                     {
                                                         ["iamcsr"] = token
                                                     });

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var status = response.Data;
            if (status.StatusCode / 100 == 2 && SuccessErrorCodes.Contains(status.Code))
                return response.Cookies;

            throw MakeInvalidResponseError(status);
        }

        internal static void LogOut(HttpCookies cookies, string tld, RestClient rest)
        {
            // It's ok to have 2XX or 3XX HTTP status. Sometimes the server sends a redirect.
            // There's no need to follow it to complete a logout.
            var response = rest.Get(LogoutUrl(tld), Headers, cookies, maxRedirects: 0);
            if (response.HasError || (int)response.StatusCode / 100 > 3)
                throw MakeErrorOnFailedRequest(response);
        }

        // TODO: Rather return a session object or something like that
        // Returns the encryption key
        internal static byte[] Authenticate(string passphrase, HttpCookies cookies, string tld, RestClient rest)
        {
            // Fetch key derivation parameters and some other stuff
            var info = GetAuthInfo(cookies, tld, rest);

            // Decryption key
            var key = Util.ComputeKey(passphrase, info.Salt, info.IterationCount);

            // Verify that the key is correct
            // AuthInfo.EncryptionCheck contains some encrypted JSON that could be
            // decrypted and parsed to check if the passphrase is correct. We have
            // to rely here on the encrypted JSON simply not parsing correctly and
            // producing some sort of error.
            var decrypted = Util.Decrypt(info.EncryptionCheck, key).ToUtf8();

            // TODO: See if ToUtf8 could throw something

            JToken parsed = null;
            try
            {
                parsed = JToken.Parse(decrypted);
            }
            catch (JsonException)
            {
            }

            // This would be null in case of JSON exception or if Parse returned null (would it?)
            if (parsed == null)
                throw new BadCredentialsException("Passphrase is incorrect");

            return key;
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

        internal static AuthInfo GetAuthInfo(HttpCookies cookies, string tld, RestClient rest)
        {
            var info = GetWrapped<R.AuthInfo>(AuthInfoUrl(tld), cookies, rest);

            if (info.KdfMethod != "PBKDF2_AES")
                throw new UnsupportedFeatureException($"KDF method '{info.KdfMethod}' is not supported");

            return new AuthInfo(info.Iterations, info.Salt.ToBytes(), info.Passphrase.Decode64());
        }

        internal static R.Vault DownloadVault(HttpCookies cookies, string tld, RestClient rest)
        {
            return GetWrapped<R.Vault>(VaultUrl(tld), cookies, rest);
        }

        internal static byte[] DecryptSharingKey(R.Vault vaultResponse, byte[] key)
        {
            if (vaultResponse.PrivateKey.IsNullOrEmpty() || vaultResponse.SharingKey.IsNullOrEmpty())
                return null;

            var privateKeyComponents = Util.Decrypt(vaultResponse.PrivateKey.Decode64(), key).ToUtf8().Split(',');
            if (privateKeyComponents.Length != 8)
                throw new InternalErrorException("Invalid RSA key format");

            var rsaKey = new RSAParameters()
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
            return vaultResponse.Secrets
                .Select(x => ParseAccount(x, x.IsShared == "YES" ? sharingKey : vaultKey))
                .Where(x => x != null)
                .ToArray();
        }

        // Returns null on accounts that don't parse
        internal static Account ParseAccount(R.Secret secret, byte[] key)
        {
            try
            {
                var data = JsonConvert.DeserializeObject<R.SecretData>(secret.Data ?? "{}");
                return new Account(secret.Id,
                                   secret.Name ?? "",
                                   Util.DecryptStringLoose(data.Username, key),
                                   Util.DecryptStringLoose(data.Password, key),
                                   secret.Url ?? "",
                                   Util.DecryptStringLoose(secret.Note, key));
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
            var response = rest.Get<R.ResponseEnvelope<T>>(url, Headers, cookies);
            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            // Check operation status
            var envelope = response.Data;
            if (envelope.Operation.Result.Status != "success")
                throw MakeInvalidResponseError("operation failed");

            return envelope.Payload;
        }

        internal static R.StatusError GetError(R.Status status)
        {
            if (status.Errors == null || status.Errors.Length == 0)
                throw MakeInvalidResponseError($"request failed with code '{status.StatusCode}/{status.Code}' " +
                                               $"and message '{status.Message}' but error wasn't provided");

            return status.Errors[0];
        }

        internal static void FindAndSaveRememberMeToken(HttpCookies cookies, ISecureStorage storage)
        {
            var name = cookies.Keys.FirstOrDefault(x => RememberMeCookieNamePattern.IsMatch(x));
            if (name.IsNullOrEmpty())
                return;

            SaveRememberMeToken(name, cookies[name!], storage);
        }

        //
        // Private
        //

        private static BaseException MakeErrorOnFailedRequest(RestResponse response)
        {
            if (response.Error == null)
                return new InternalErrorException(
                    $"Request to {response.RequestUri} failed with HTTP status {(int)response.StatusCode}");

            return new NetworkErrorException($"Request to {response.RequestUri} failed with a network error",
                                             response.Error);
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

        //
        // Data
        //

        private const string DefaultDataCenter = "us";

        private const string ServiceName = "ZohoVault";
        private const string OAuthScope = "ZohoVault.secrets.READ";

        private static readonly string LoginPageUrl =
            $"https://accounts.zoho.com/oauth/v2/auth?response_type=code&scope={OAuthScope}&prompt=consent";

        private static string LookupUrl(string tld, string username) =>
            $"https://accounts.zoho.{tld}/signin/v2/lookup/{username}";

        private static string LogInUrl(UserInfo user, long timestamp) =>
            $"https://accounts.zoho.{user.Tld}/signin/v2/primary/{user.Id}/password?digest={user.Digest}&cli_time={timestamp}&servicename={ServiceName}";

        private static string TotpUrl(UserInfo user, long timestamp) =>
            $"https://accounts.zoho.{user.Tld}/signin/v2/secondary/{user.Id}/totp?digest={user.Digest}&cli_time={timestamp}&servicename={ServiceName}";

        private static string TrustUrl(UserInfo user) =>
            $"https://accounts.zoho.{user.Tld}/signin/v2/secondary/{user.Id}/trust";

        private static string AuthInfoUrl(string tld) =>
            $"https://vault.zoho.{tld}/api/json/login?OPERATION_NAME=GET_LOGIN";

        private static string VaultUrl(string tld) =>
            $"https://vault.zoho.{tld}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=-1";

        private static string LogoutUrl(string tld) => $"https://accounts.zoho.{tld}/logout?servicename=ZohoVault";

        private const string UserAgent =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";

        private static readonly string[] SuccessErrorCodes = {"SI200", "SI300", "SI301", "SI302", "SI303", "SI304"};

        // Important! Most of the requests fail without a valid User-Agent header
        private static readonly Dictionary<string, string> Headers =
            new Dictionary<string, string> { { "User-Agent", UserAgent } };

        private static readonly Regex RememberMeCookieNamePattern = new Regex(@"^IAM.*TFATICKET_\d+$");

        private const string RememberMeTokenKey = "remember-me-token-key";
        private const string RememberMeTokenValue = "remember-me-token-value";
    }
}
