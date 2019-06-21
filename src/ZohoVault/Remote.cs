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

    // TODO: Rename to Client to align with the other libraries
    internal static class Remote
    {
        public static string Login(string username, string password, Ui ui, RestClient rest)
        {
            // TODO: This should probably be random
            const string iamcsrcoo = "12345678-1234-1234-1234-1234567890ab";

            // POST
            var response = rest.PostForm(
                url: LoginUrl,
                parameters: new Dictionary<string, object>
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"IS_AJAX", "true"},
                    {"remember", "-1"},
                    {"hide_reg_link", "false"},
                    {"iamcsrcoo", iamcsrcoo}
                },
                cookies: new Dictionary<string, string> {{ "iamcsr", iamcsrcoo }});

            // TODO: Should not throw network errors on HTTP 404 and stuff like that
            if (!response.IsSuccessful)
                throw MakeNetworkError(response.Error);

            // The returned text is JavaScript which is supposed to call some functions on the
            // original page. "showsuccess" is called when everything went well. "switchto" is a
            // MFA poor man's redirect.
            if (response.Content.StartsWith("switchto("))
                response = LoginMfa(response, iamcsrcoo, ui, rest);

            if (!response.Content.StartsWith("showsuccess"))
                throw new BadCredentialsException("Login failed, most likely the credentials are invalid");

            // Extract the token from the response cookies
            var cookie = response.Cookies.GetOrDefault("IAMAUTHTOKEN", "");
            if (cookie.IsNullOrEmpty())
                throw MakeInvalidResponse("Auth cookie not found");

            return cookie;
        }

        internal static RestResponse LoginMfa(RestResponse loginResponse, string iamcsrcoo, Ui ui, RestClient rest)
        {
            var url = ParseSwitchTo(loginResponse.Content);

            // We need use all the cookies from the login to get the page and submit the code
            var cookies = new Dictionary<string, string> {{ "iamcsr", iamcsrcoo }}.Merge(loginResponse.Cookies);

            // First get the MFA page
            var page = rest.Get(url: url, cookies: cookies);
            if (!page.IsSuccessful)
                throw MakeNetworkError(page.Error);

            // Ask the user to enter the code
            var code = RequestMfaCode(page, ui);

            // Now submit the form with the MFA code
            var verifyResponse = rest.PostForm(
                url: "https://accounts.zoho.com/tfa/verify",
                parameters: new Dictionary<string, object>
                {
                    {"remembertfa", "false"},
                    {"code", code.Code},
                    {"iamcsrcoo", iamcsrcoo},
                },
                cookies: cookies);

            // Specific error: means the MFA code wasn't correct
            if (verifyResponse.Content == "invalid_code")
                throw new BadMultiFactorException("Invalid second factor code");

            // Generic error
            if (!verifyResponse.IsSuccessful)
                throw MakeNetworkError(verifyResponse.Error);

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

        internal static string ParseSwitchTo(string response)
        {
            // Decode "switchto('https\\x3A\\x2F\\x2Faccounts.zoho.com\\x2Ftfa\\x2Fauth\\x3Fserviceurl\\x3Dhttps\\x253A\\x252F\\x252Fvault.zoho.com');"
            // to "https://accounts.zoho.com/tfa/auth?serviceurl=https%3A%2F%2Fvault.zoho.com"
            var findString = Regex.Match(response, "switchto\\('(.*)'\\)");
            if (!findString.Success)
                throw MakeInvalidResponse("Unexpected 'switchto' format");

            var escaped = findString.Groups[1].Value;
            return Regex.Replace(escaped, "\\\\x(..)", m => m.Groups[1].Value.DecodeHex().ToUtf8());
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
                throw MakeNetworkError(response.Error);

            return response.Content;
        }

        internal static T Get<T>(string url, string token, RestClient rest)
        {
            // GET
            var response = rest.Get<R.ResponseEnvelope<T>>(url, HeadersForGet(token));
            if (!response.IsSuccessful)
                throw MakeNetworkError(response.Error);

            if (url == VaultUrl)
                File.WriteAllText("c:/devel/vault.json", response.Content);

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
                { "Authorization", $"Zoho-authtoken {token}" },
                { "User-Agent", "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1)" },
                { "requestFrom", "vaultmobilenative" },
            };
        }

        //
        // Private
        //

        private static NetworkErrorException MakeNetworkError(Exception original)
        {
            return new NetworkErrorException("Network error occurred", original);
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
