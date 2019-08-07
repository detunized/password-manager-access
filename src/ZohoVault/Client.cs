// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    using R = Response;
    using HttpCookies = Dictionary<string, string>;

    internal static class Client
    {
        public static Account[] OpenVault(string username, string password, string passphrase, Ui ui, RestClient rest)
        {
            var cookies = Login(username, password, ui, rest);
            try
            {
                var key = Authenticate(passphrase, cookies, rest);
                var vaultResponse = DownloadVault(cookies, rest);

                return ParseAccounts(vaultResponse, key);
            }
            finally
            {
                Logout(cookies, rest);
            }
        }

        //
        // Internal
        //

        internal static HttpCookies Login(string username, string password, Ui ui, RestClient rest)
        {
            // OAuth flow:
            //   1. login page (potential captcha)
            //   2. MFA page (optional, only when MFA is enabled)
            //   3. Approve page
            //   4. Redirect URL with OAuth temporary token
            //   5. Exchange token for permanent token

            // 1a. Fetch the login page for cookies
            var loginPage = rest.Get(LoginPageUrl, Headers);
            if (!loginPage.IsSuccessful)
                throw MakeErrorOnFailedRequest(loginPage);

            // TODO: Check for errors
            var csrToken = loginPage.Cookies["iamcsr"];

            // 1b. Submit the login form
            var response = rest.PostForm(
                AuthUrl,
                parameters: new Dictionary<string, object>
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"cli_time", DateTimeOffset.Now.ToUnixTimeMilliseconds()},
                    {"iamcsrcoo", csrToken},
                    {"servicename", ServiceName},
                    {"serviceurl", ServiceUrl},
                },
                headers: Headers,
                cookies: loginPage.Cookies); // TODO: See if we need all the cookies

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
                // Sometimes the web login redirects to some kind of message or announcement or whatever.
                // Probably the only way to deal with that is either show the actual browser or tell
                // the user to login manually and dismiss the message.
                var url = ExtractSwitchToUrl(response.Content);
                if (url.StartsWith("https://accounts.zoho.com/tfa/auth"))
                    response = LoginMfa(response, ui, rest);
                else
                    throw MakeInvalidResponse($"Unexpected 'switchto' url: '{url}'");
            }

            // Should be when all is good!
            if (response.Content.StartsWith("showsuccess("))
            {
                var url = ExtractShowSuccessUrl(response.Content);
                if (url.StartsWith("https://accounts.zoho.com/oauth/v2/approve"))
                {
                    response = Approve(response, rest);
                    if (!response.Content.StartsWith("showsuccess("))
                        throw MakeInvalidResponse($"Unexpected response: {response.Content}");
                }

                return response.Cookies;
            }

            throw new BadCredentialsException("Login failed, most likely the credentials are invalid");
        }

        internal static void Logout(HttpCookies cookies, RestClient rest)
        {
            var response = rest.Get(
                LogoutUrl,
                Headers,
                cookies);

            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);
        }

        // TODO: Rather return a session object or something like that
        // Returns the encryption key
        internal static byte[] Authenticate(string passphrase, HttpCookies cookies, RestClient rest)
        {
            // Fetch key derivation parameters and some other stuff
            var info = GetAuthInfo(cookies, rest);

            // Decryption key
            var key = Crypto.ComputeKey(passphrase, info.Salt, info.IterationCount);

            // Verify that the key is correct
            // AuthInfo.EncryptionCheck contains some encrypted JSON that could be
            // decrypted and parsed to check if the passphrase is correct. We have
            // to rely here on the encrypted JSON simply not parsing correctly and
            // producing some sort of error.
            var decrypted = Crypto.Decrypt(info.EncryptionCheck, key).ToUtf8();

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

        internal static R.Vault DownloadVault(HttpCookies cookies, RestClient rest)
        {
            return GetWrapped<R.Vault>(VaultUrl, cookies, rest);
        }

        internal static Account[] ParseAccounts(R.Vault vaultResponse, byte[] key)
        {
            // TODO: Test on non account type secrets!
            // TODO: Test on accounts with missing fields!
            return vaultResponse.Secrets
                .Select(x => ParseAccount(x, key))
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
                                   Crypto.DecryptString(data.Username, key),
                                   Crypto.DecryptString(data.Password, key),
                                   secret.Url,
                                   Crypto.DecryptString(secret.Note, key));
            }
            catch (JsonException)
            {
                // If it doesn't parse then it's some other kind of unsupported secret type. Ignore.
                return null;
            }
        }

        internal static RestResponse LoginMfa(RestResponse loginResponse, Ui ui, RestClient rest)
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
            foreach (var name in "_iamtt dcl_pfx_lcnt iamcsr JSESSIONID stk tfa_ac".Split(' '))
                cookies[name] = loginResponse.Cookies[name];

            // Now submit the form with the MFA code
            var verifyResponse = rest.PostForm(
                endpoint: VerifyUrl,
                parameters: new Dictionary<string, object>
                {
                    {"remembertfa", "false"},
                    {"code", code.Code},
                    {"iamcsrcoo", cookies["iamcsr"]},
                    {"servicename", ServiceName},
                    {"serviceurl", ServiceUrl},
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

            return verifyResponse;
        }

        internal static Ui.Passcode RequestMfaCode(RestResponse mfaPage, Ui ui)
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

        // TODO: OAuth is currently not working with the Zoho server, so this method should not be called.
        //       It requires some additional info that should be provided by the app.
        internal static RestResponse Approve(RestResponse loginResponse, RestClient rest)
        {
            var response = rest.PostForm(
                endpoint: "https://accounts.zoho.com/oauth/v2/approve",
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

        internal static AuthInfo GetAuthInfo(HttpCookies cookies, RestClient rest)
        {
            var info = GetWrapped<R.AuthInfo>(AuthInfoUrl, cookies, rest);

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

        //
        // Data
        //

        // TODO: Simplify this url
        private const string ServiceName = "ZohoVault";
        private const string ServiceUrl = "https://vault.zoho.com";
        private const string OAuthScope = "ZohoVault.secrets.READ";

        private static readonly string LoginPageUrl =
            $"https://accounts.zoho.com/oauth/v2/auth?response_type=code&scope={OAuthScope}&prompt=consent";

        private const string AuthUrl =
            "https://accounts.zoho.com/signin/auth";

        private const string AuthInfoUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN";

        private const string VerifyUrl =
            "https://accounts.zoho.com/tfa/verify";

        private const string VaultUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=200";

        private const string LogoutUrl =
            "https://accounts.zoho.com/logout?servicename=ZohoVault&serviceurl=https://www.zoho.com/vault/";

        private const string UserAgent =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";

        // Important! Most of the requests fail without a valid User-Agent header
        private static readonly Dictionary<string, string> Headers =
            new Dictionary<string, string> { { "User-Agent", UserAgent } };
    }
}
