// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    using R = Response;

    public class ClientInfo
    {
        public readonly string ClientId;
        public readonly string RedirectUrl;

        public ClientInfo(string clientId, string redirectUrl)
        {
            ClientId = clientId;
            RedirectUrl = redirectUrl;
        }
    }

    internal static class Client
    {
        // Important! Most of the requests fail without a valid User-Agent header
        private const string UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";
        private static readonly Dictionary<string, string> Headers = new Dictionary<string, string> { { "User-Agent", UserAgent } };

        private const string ServiceName = "ZohoVault";
        private const string OAuthScope = "ZohoVault.secrets.READ";

        private static string GetLoginPageUrl(ClientInfo clientInfo)
        {
            return $"https://accounts.zoho.com/oauth/v2/auth?response_type=code&client_id={clientInfo.ClientId}&scope={OAuthScope}&redirect_uri={clientInfo.RedirectUrl}&prompt=consent";
        }

        private static string GetServiceUrl(ClientInfo clientInfo)
        {
            return "https://vault.zoho.com";
        }

        public static string Login(string username, string password, Ui ui, RestClient rest)
        {
            var clientInfo = new ClientInfo("1000.BEAP2L2VJXF340958YSBLH69MCVXIH",
                                            "https://detunized.net/zohooauth");

            // OAuth flow:
            //   1. login page (potential captcha)
            //   2. MFA page (optional, only when MFA is enabled)
            //   3. Approve page
            //   4. Redirect URL with OAuth temporary token
            //   5. Exchange token for permanent token

            // 1a. Fetch the login page for cookies
            var loginPage = rest.Get(GetLoginPageUrl(clientInfo), Headers);
            if (!loginPage.IsSuccessful)
                throw MakeErrorOnFailedRequest(loginPage);

            // TODO: Check for errors
            var csrToken = loginPage.Cookies["iamcsr"];

            // 1b. Submit the login form
            var response = rest.PostForm(
                "https://accounts.zoho.com/signin/auth",
                parameters: new Dictionary<string, object>
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"cli_time", DateTimeOffset.Now.ToUnixTimeMilliseconds()},
                    {"iamcsrcoo", csrToken},
                    {"servicename", ServiceName},
                    {"serviceurl", GetServiceUrl(clientInfo)},
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
                    response = LoginMfa(response, clientInfo, ui, rest);
                else
                    throw MakeInvalidResponse($"Unexpected 'switchto' url: '{url}'");
            }

            // Should be when all is good!
            if (response.Content.StartsWith("showsuccess("))
            {
                var url = ExtractShowSuccessUrl(response.Content);
                if (url.StartsWith("https://accounts.zoho.com/oauth/v2/approve"))
                    response = Approve(response, clientInfo, rest);
                else
                    throw MakeInvalidResponse($"Unexpected 'showsuccess' url: '{url}'");
            }
            else
            {
                throw new BadCredentialsException("Login failed, most likely the credentials are invalid");
            }

            // Extract the token from the response cookies
            return response.Content;
        }

        public static void Logout(string token, RestClient rest)
        {
            Get($"{LogoutUrl}?AUTHTOKEN={token}", token, rest);
        }

        // TODO: Rather return a session object or something like that
        // Returns the encryption key
        public static byte[] Authenticate(string token, string passphrase, RestClient rest)
        {
            // Fetch key derivation parameters and some other stuff
            var info = GetAuthInfo(token, rest);

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

        public static R.Vault DownloadVault(string token, RestClient rest)
        {
            return Get<R.Vault>(VaultUrl, token, rest);
        }

        //
        // Internal
        //

        internal static RestResponse LoginMfa(RestResponse loginResponse,
                                              ClientInfo clientInfo,
                                              Ui ui,
                                              RestClient rest)
        {
            var url = ExtractSwitchToUrl(loginResponse.Content);

            // First get the MFA page. We need use all the cookies
            // from the login to get the page and submit the code.
            var page = rest.Get(url: url, headers: Headers, cookies: loginResponse.Cookies);
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
                url: "https://accounts.zoho.com/tfa/verify",
                parameters: new Dictionary<string, object>
                {
                    {"remembertfa", "false"},
                    {"code", code.Code},
                    {"iamcsrcoo", cookies["iamcsr"]},
                    {"servicename", ServiceName},
                    {"serviceurl", GetServiceUrl(clientInfo)},
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

        internal static RestResponse Approve(RestResponse loginResponse, ClientInfo clientInfo, RestClient rest)
        {
            var response = rest.PostForm(
                url: "https://accounts.zoho.com/oauth/v2/approve",
                parameters: new Dictionary<string, object>
                {
                    {"response_type", "code"},
                    {"client_id", clientInfo.ClientId},
                    {"scope", OAuthScope},
                    {"redirect_uri", clientInfo.RedirectUrl},
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

        internal static AuthInfo GetAuthInfo(string token, RestClient rest)
        {
            var info = Get<R.AuthInfo>(AuthUrl, token, rest);

            if (info.KdfMethod != "PBKDF2_AES")
                throw MakeInvalidResponse("Only PBKDF2/AES is supported");

            return new AuthInfo(info.Iterations, info.Salt.ToBytes(), info.Passphrase.Decode64());
        }

        internal static string Get(string url, string token, RestClient rest)
        {
            // GET
            var response = rest.Get(url, HeadersForGet(token));
            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            return response.Content;
        }

        internal static T Get<T>(string url, string token, RestClient rest)
        {
            // GET
            var response = rest.Get<R.ResponseEnvelope<T>>(url, HeadersForGet(token));
            if (!response.IsSuccessful)
                throw MakeErrorOnFailedRequest(response);

            // TODO: Remove this!
            if (url == VaultUrl)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("I'm writing file to the disk. REMOVE ME!!!");
                File.WriteAllText("c:/devel/vault.json", response.Content);
            }

            // Check operation status
            var envelope = response.Data;
            if (envelope.Operation.Result.Status != "success")
                throw MakeInvalidResponseFormat();

            return envelope.Payload;
        }

        internal static Dictionary<string, string> HeadersForGet(string token)
        {
            return new Dictionary<string, string>
            {
                // TODO: This is probably not needed anymore
                { "Authorization", $"Zoho-authtoken {token}" },
                { "User-Agent", "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1)" },
                { "requestFrom", "vaultmobilenative" },
            };
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
        private const string LoginUrl =
            "https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false";
        private const string LogoutUrl = "https://accounts.zoho.com/apiauthtoken/delete";
        private const string AuthUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN";
        private const string VaultUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=200";
    }
}
