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

namespace PasswordManagerAccess.ZohoVault
{
    using HttpCookies = Dictionary<string, string>;
    using R = Response;

    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string password,
                                          string passphrase,
                                          Ui ui,
                                          ISecureStorage storage,
                                          IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // This token is needed to access other pages of the login flow. It's sent via headers,
            // cookies and in the request data.
            var token = RequestToken(rest);

            // TLD is determined by the region/data center. Each user is associated with a specific
            // region.
            var tld = GetRegionTld(username, token, rest);

            // Perform the login dance that possibly involves the MFA steps. The cookies are later
            // used by the subsequent requests.
            //
            // TODO: It would be ideal to figure out which cookies are needed for general
            // cleanliness. It was too many of them and so they are now passed altogether a bundle
            // between the requests.
            var cookies = Login(username, password, token, tld, ui, storage, rest);

            try
            {
                var vaultKey = Authenticate(passphrase, cookies, tld, rest);
                var vaultResponse = DownloadVault(cookies, tld, rest);
                var sharingKey = DecryptSharingKey(vaultResponse, vaultKey);

                return ParseAccounts(vaultResponse, vaultKey, sharingKey);
            }
            finally
            {
                Logout(cookies, tld, rest);
            }
        }

        //
        // Internal
        //

        internal static string RequestToken(RestClient rest)
        {
            var loginPage = rest.Get(LoginPageUrl, Headers);
            if (!loginPage.IsSuccessful)
                throw MakeErrorOnFailedRequest(loginPage);

            var token = loginPage.Cookies.GetOrDefault("iamcsr", "");
            if (token.IsNullOrEmpty())
                throw new InternalErrorException("Unexpected response: 'iamcsr' cookie is not set by the server");

            return token;
        }

        internal static string GetRegionTld(string username, string csrToken, RestClient rest)
        {
            var response = rest.PostForm<R.Lookup>(
                $"{LookupUrl}/{username}",
                new Dictionary<string, object>
                {
                    { "mode", "primary" },
                    { "cli_time", DateTimeOffset.Now.ToUnixTimeMilliseconds() },
                    { "servicename", ServiceName },
                    { "serviceurl", ServiceUrl("com") },
                },
                headers: new Dictionary<string, string> { { "X-ZCSRF-TOKEN", $"iamcsrcoo={csrToken}" } },
                cookies: new Dictionary<string, string> { { "iamcsr", csrToken } });

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            var result = response.Data;
            string dataCenter;

            if (result.StatusCode / 100 == 2)
            {
                dataCenter = result.Result?.DataCenter;
            }
            else if (result.Errors?.Length > 0)
            {
                switch (result.Errors[0].Code)
                {
                case "U400": // User exists in another DC
                    dataCenter = result.Redirect?.DataCenter;
                    break;
                case "U401": // User doesn't exist
                    throw new BadCredentialsException("The username is invalid");
                default:
                    throw new InternalErrorException("Unexpected response");
                }
            }
            else
            {
                throw new InternalErrorException("Unexpected response");
            }

            return DataCenterToTld(dataCenter);
        }

        internal static string DataCenterToTld(string dataCenter)
        {
            if (dataCenter.IsNullOrEmpty())
                throw new InternalErrorException("Unexpected response (no data center found)");

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

        internal static HttpCookies Login(string username,
                                          string password,
                                          string token,
                                          string tld,
                                          Ui ui,
                                          ISecureStorage storage,
                                          RestClient rest)
        {
            var cookies = new Dictionary<string, string> { { "iamcsr", token } };

            // Check if we have a "remember me" token saved from one of the previous sessions
            var (rememberMeKey, rememberMeValue) = LoadRememberMeToken(storage);
            bool haveRememberMe = !rememberMeKey.IsNullOrEmpty() && !rememberMeValue.IsNullOrEmpty();
            if (haveRememberMe)
                cookies[rememberMeKey] = rememberMeValue;

            // Submit the login form
            var response = rest.PostForm(
                AuthUrl(tld),
                parameters: new Dictionary<string, object>
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"cli_time", DateTimeOffset.Now.ToUnixTimeMilliseconds()},
                    {"iamcsrcoo", token},
                    {"servicename", ServiceName},
                    {"serviceurl", ServiceUrl(tld)},
                },
                headers: Headers,
                cookies: cookies);

            // TODO: Handle captcha
            // Need to show captcha: showhiperror('HIP_REQUIRED')
            // Captcha is invalid: showhiperror('HIP_INVALID')

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            // The returned text is JavaScript which is supposed to call some functions on the
            // original page. "showsuccess" is called when everything went well. "switchto" is a
            // MFA poor man's redirect.
            if (response.Content.StartsWith("switchto("))
            {
                // The "remember me" token didn't work, so it must be outdated or corrupted.
                if (haveRememberMe)
                    EraseRememberMeToken(storage);

                // Sometimes the web login redirects to some kind of message or announcement or whatever.
                // Probably the only way to deal with that is either show the actual browser or tell
                // the user to login manually and dismiss the message.
                var url = ExtractSwitchToUrl(response.Content);
                if (Regex.IsMatch(url, $"^https://accounts.zoho.{tld}/[mt]fa/auth"))
                    response = LoginMfa(response, tld, ui, storage, rest);
                else
                    throw MakeInvalidResponse($"Unexpected 'switchto' url: '{url}'");
            }

            // Should be when all is good!
            if (response.Content.StartsWith("showsuccess("))
            {
                var url = ExtractShowSuccessUrl(response.Content);
                if (url.StartsWith($"https://accounts.zoho.{tld}/oauth/v2/approve"))
                {
                    response = Approve(response, tld, rest);
                    if (!response.Content.StartsWith("showsuccess("))
                        throw MakeInvalidResponse($"Unexpected response: {response.Content}");
                }

                return response.Cookies;
            }

            throw new BadCredentialsException("Login failed, most likely the credentials are invalid");
        }

        internal static void Logout(HttpCookies cookies, string tld, RestClient rest)
        {
            var response = rest.Get(LogoutUrl(tld), Headers, cookies);
            if (!response.IsSuccessful)
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

            return Crypto.DecryptRsa(vaultResponse.SharingKey.DecodeHex(), rsaKey, RSAEncryptionPadding.Pkcs1);
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
                var data = JsonConvert.DeserializeObject<R.SecretData>(secret.Data);
                return new Account(secret.Id,
                                   secret.Name,
                                   Util.DecryptString(data.Username, key),
                                   Util.DecryptString(data.Password, key),
                                   secret.Url,
                                   Util.DecryptString(secret.Note, key));
            }
            catch (JsonException)
            {
                // If it doesn't parse then it's some other kind of unsupported secret type. Ignore.
                return null;
            }
        }

        internal static RestResponse<string> LoginMfa(RestResponse<string> loginResponse,
                                                      string tld,
                                                      Ui ui,
                                                      ISecureStorage storage,
                                                      RestClient rest)
        {
            var url = ExtractSwitchToUrl(loginResponse.Content);

            // First get the MFA page. We need use all the cookies
            // from the login to get the page and submit the code.
            var page = rest.Get(endpoint: url, headers: Headers, cookies: loginResponse.Cookies);
            if (!page.IsSuccessful)
                throw MakeErrorOnFailedRequest(page);

            // Ask the user to enter the code
            var code = RequestMfaCode(page, ui);

            // TODO: See which cookies are needed
            var cookies = new Dictionary<string, string>();
            foreach (var name in "_iamtt iamcsr JSESSIONID stk tfa_ac".Split(' '))
                cookies[name] = loginResponse.Cookies[name];

            // Now submit the form with the MFA code
            var verifyResponse = rest.PostForm(
                endpoint: VerifyUrl(tld),
                parameters: new Dictionary<string, object>
                {
                    { "remembertfa", code.RememberMe ? "true" : "false" },
                    { "code", code.Code },
                    { "iamcsrcoo", cookies["iamcsr"] },
                    { "servicename", ServiceName },
                    { "serviceurl", ServiceUrl(tld) },
                },
                headers: Headers,
                cookies: cookies);

            // Specific error: means the MFA code wasn't correct
            if (verifyResponse.Content == "invalid_code")
                throw new BadMultiFactorException("Invalid second factor code");

            // Generic error
            if (!verifyResponse.IsSuccessful)
                throw MakeErrorOnFailedRequest(verifyResponse);

            if (!verifyResponse.Content.StartsWith("showsuccess("))
                throw MakeInvalidResponse("Verify MFA failed");

            // Store remember me token for the next sessions
            if (code.RememberMe)
            {
                var key = verifyResponse.Cookies.Keys.Where(x => x.StartsWith("IAMTFATICKET_")).FirstOrDefault();
                if (!key.IsNullOrEmpty())
                    SaveRememberMeToken(storage, key, verifyResponse.Cookies[key]);
            }

            return verifyResponse;
        }

        internal static Ui.Passcode RequestMfaCode(RestResponse<string> mfaPage, Ui ui)
        {
            Ui.Passcode code = null;
            var html = mfaPage.Content;

            if (html.Contains("Google Authenticator"))
                code = ui.ProvideGoogleAuthPasscode(0);
            else if (html.Contains("Yubikey"))
                code = ui.ProvideYubiKeyPasscode(0);
            else
                throw new UnsupportedFeatureException("MFA method is not supported");

            if (code == Ui.Passcode.Cancel)
                throw new CanceledMultiFactorException("Second factor step is canceled by the user");

            return code;
        }

        internal static string ExtractSwitchToUrl(string response)
        {
            // Decode "switchto('https\\x3A\\x2F\\x2Faccounts.zoho.com\\x2Ftfa\\x2Fauth\\x3Fserviceurl\\x3Dhttps\\x253A\\x252F\\x252Fvault.zoho.com');"
            // to "https://accounts.zoho.com/tfa/auth?serviceurl=https%3A%2F%2Fvault.zoho.com"
            var findString = Regex.Match(response, "switchto\\('(.*)'\\)");
            if (!findString.Success)
                throw MakeInvalidResponse("Unexpected 'switchto' format");

            return UnescapeJsUrl(findString.Groups[1].Value);
        }

        internal static string ExtractShowSuccessUrl(string response)
        {
            // Decode "TODO: "
            // to "TODO: "
            var findString = Regex.Match(response, "showsuccess\\('(.*?)',");
            if (!findString.Success)
                throw MakeInvalidResponse("Unexpected 'showsuccess' format");

            return UnescapeJsUrl(findString.Groups[1].Value);
        }

        internal static string UnescapeJsUrl(string escaped)
        {
            return Regex.Replace(escaped, "\\\\x(..)", m => m.Groups[1].Value.DecodeHex().ToUtf8());
        }

        // TODO: Is this even used?
        // TODO: OAuth is currently not working with the Zoho server, so this method should not be called.
        //       It requires some additional info that should be provided by the app.
        internal static RestResponse<string> Approve(RestResponse loginResponse, string tld, RestClient rest)
        {
            var response = rest.PostForm(
                endpoint: ApproveUrl(tld),
                parameters: new Dictionary<string, object>
                {
                    {"response_type", "code"},
                    {"client_id", "TODO: ClientId"},
                    {"scope", OAuthScope},
                    {"redirect_uri", "TODO: RedirectUrl"},
                    {"prompt", "consent"},
                    {"approvedScope", OAuthScope},
                    {"iamcsrcoo", loginResponse.Cookies["iamcsr"]},
                    {"is_ajax", "true"},
                    {"approvedOrgs", ""},
                    {"implicitGranted", "false"},
                },
                headers: Headers,
                cookies: loginResponse.Cookies); // TODO: See if need all the cookies

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            return response;
        }

        internal struct AuthInfo
        {
            public AuthInfo(int iterationCount, byte[] salt, byte[] encryptionCheck)
            {
                IterationCount = iterationCount;
                Salt = salt;
                EncryptionCheck = encryptionCheck;
            }

            public int IterationCount { get; }
            public byte[] Salt;
            public byte[] EncryptionCheck;
        }

        internal static AuthInfo GetAuthInfo(HttpCookies cookies, string tld, RestClient rest)
        {
            var info = GetWrapped<R.AuthInfo>(AuthInfoUrl(tld), cookies, rest);

            if (info.KdfMethod != "PBKDF2_AES")
                throw MakeInvalidResponse("Only PBKDF2/AES is supported");

            return new AuthInfo(info.Iterations, info.Salt.ToBytes(), info.Passphrase.Decode64());
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
                throw MakeInvalidResponseFormat();

            return envelope.Payload;
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

        private static InternalErrorException MakeInvalidResponseFormat()
        {
            return MakeInvalidResponse("Invalid response format");
        }

        private static InternalErrorException MakeInvalidResponse(string message, Exception original = null)
        {
            return new InternalErrorException(message, original);
        }

        private static (string key, string value) LoadRememberMeToken(ISecureStorage storage)
        {
            return (storage.LoadString(RememberMeTokenKey), storage.LoadString(RememberMeTokenValue));
        }

        private static void SaveRememberMeToken(ISecureStorage storage, string key, string value)
        {
            storage.StoreString(RememberMeTokenKey, key);
            storage.StoreString(RememberMeTokenValue, value);
        }

        private static void EraseRememberMeToken(ISecureStorage storage)
        {
            SaveRememberMeToken(storage, null, null);
        }

        //
        // Data
        //

        private const string ServiceName = "ZohoVault";
        private const string OAuthScope = "ZohoVault.secrets.READ";

        private static string ServiceUrl(string tld) => $"https://vault.zoho.{tld}";

        private static readonly string LoginPageUrl =
            $"https://accounts.zoho.com/oauth/v2/auth?response_type=code&scope={OAuthScope}&prompt=consent";

        private const string LookupUrl = "https://accounts.zoho.com/signin/v2/lookup";

        private static string AuthUrl(string tld) => $"https://accounts.zoho.{tld}/signin/auth";

        private static string AuthInfoUrl(string tld) =>
            $"https://vault.zoho.{tld}/api/json/login?OPERATION_NAME=GET_LOGIN";

        private static string VerifyUrl(string tld) => $"https://accounts.zoho.{tld}/tfa/verify";

        private static string ApproveUrl(string tld) => $"https://accounts.zoho.{tld}/oauth/v2/approve";

        private static string VaultUrl(string tld) =>
            $"https://vault.zoho.{tld}/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=200";

        private static string LogoutUrl(string tld) => $"https://accounts.zoho.{tld}/logout?servicename=ZohoVault";

        private const string UserAgent =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";

        // Important! Most of the requests fail without a valid User-Agent header
        private static readonly Dictionary<string, string> Headers =
            new Dictionary<string, string> { { "User-Agent", UserAgent } };

        private const string RememberMeTokenKey = "remember-me-token-key";
        private const string RememberMeTokenValue = "remember-me-token-value";
    }
}
