// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using RestSharp;

namespace PasswordManagerAccess.ZohoVault
{
    // TODO: Rename to Client to align with the other libraries
    public static class Remote
    {
        // TODO: Simplify this url
        private const string LoginUrl =
            "https://accounts.zoho.com/login?scopes=ZohoVault/vaultapi,ZohoContacts/photoapi&appname=zohovault/2.5.1&serviceurl=https://vault.zoho.com&hide_remember=true&hide_logo=true&hidegooglesignin=false&hide_signup=false";
        private const string LogoutUrl = "https://accounts.zoho.com/apiauthtoken/delete";
        private const string AuthUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=GET_LOGIN";
        private const string VaultUrl =
            "https://vault.zoho.com/api/json/login?OPERATION_NAME=OPEN_VAULT&limit=200";

        public static string Login(string username, string password)
        {
            using (var webClient = new WebClient())
                return Login(username, password, webClient);
        }

        public static string Login(string username, string password, IWebClient webClient)
        {
            // TODO: This should probably be random
            const string iamcsrcoo = "12345678-1234-1234-1234-1234567890ab";

            // Set a cookie with some random gibberish
            var defaultCookies = new Dictionary<string, string> {{ "iamcsr", iamcsrcoo }};

            // POST
            var response = webClient.Post(
                LoginUrl,
                new Dictionary<string, object>
                {
                    {"LOGIN_ID", username},
                    {"PASSWORD", password},
                    {"IS_AJAX", "true"},
                    {"remember", "-1"},
                    {"hide_reg_link", "false"},
                    {"iamcsrcoo", iamcsrcoo}
                },
                null,
                defaultCookies);

            // TODO: Should not throw network errors on HTTP 404 and stuff like that
            if (!response.IsSuccessful)
                throw MakeNetworkError(response.ErrorException);

            // The returned text is JavaScript which is supposed to call some functions on the
            // original page. "showsuccess" is called when everything went well.
            var responseText = response.Content;

            // MFA poor man's redirect
            if (responseText.StartsWith("switchto("))
            {
                var url = ParseSwitchTo(responseText);
                var mfaPage = webClient.Get(url, null, null).Content;
                try
                {
                    var res = webClient.Post(
                        "https://accounts.zoho.com/tfa/verify",
                        new Dictionary<string, object>
                        {
                            {"remembertfa", "false"},
                            {"code", "TODO: MFA code"},
                            {"iamcsrcoo", iamcsrcoo},
                        },
                        null,
                        null);
                }
                catch (WebException e)
                {
                    throw MakeNetworkError(e);
                }

                throw new NotImplementedException("TODO");
            }
            else if (!responseText.StartsWith("showsuccess"))
            {
                throw new BadCredentialsException("Login failed, most likely the credentials are invalid");
            }

            // Extract the token from the response cookies
            var cookie = response.Cookies.Where(x => x.Name == "IAMAUTHTOKEN").FirstOrDefault()?.Value;
            if (cookie.IsNullOrEmpty())
                throw MakeInvalidResponse("Auth cookie not found");

            return cookie;
        }

        public static void Logout(string token)
        {
            using (var webClient = new WebClient())
                Logout(token, webClient);
        }

        public static void Logout(string token, IWebClient webClient)
        {
            var url = string.Format("{0}?AUTHTOKEN={1}", LogoutUrl, token);
            Get(url, token, webClient);
        }

        // TODO: Rather return a session object or something like that
        // Returns the encryption key
        public static byte[] Authenticate(string token, string passphrase, IWebClient webClient)
        {
            // Fetch key derivation parameters and some other stuff
            var info = GetAuthInfo(token, webClient);

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

        public static JToken DownloadVault(string token, byte[] key, IWebClient webClient)
        {
            return GetJsonObject(VaultUrl, token, webClient);
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

            [RestSharp.Deserializers.DeserializeAs(Name = "ITERATION")]
            public int IterationCount { get; }
            public byte[] Salt;
            public byte[] EncryptionCheck;
        }

        internal static AuthInfo GetAuthInfo(string token, IWebClient webClient)
        {
            return GetJsonObject<AuthInfo>(AuthUrl, token, webClient);

            var response = GetJsonObject(AuthUrl, token, webClient);

            if (response.StringAtOrNull("LOGIN") != "PBKDF2_AES")
                throw MakeInvalidResponse("Only PBKDF2/AES is supported");

            // Extract and convert important information
            var iterations = response.IntAtOrNull("ITERATION");
            var salt = response.StringAtOrNull("SALT");
            var passphrase = response.StringAtOrNull("PASSPHRASE");

            if (iterations == null || salt == null || passphrase == null)
                throw MakeInvalidResponseFormat();

            return new AuthInfo(iterations.Value, salt.ToBytes(), passphrase.Decode64());
        }

        internal static IRestResponse<T> Get<T>(string url, string token, IWebClient webClient) where T: new()
        {
            // Set headers
            var headers = new Dictionary<string, string>
            {
                { "Authorization", $"Zoho-authtoken {token}" },
                { "User-Agent", "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1" },
                { "requestFrom", "vaultmobilenative" },
            };

            // GET
            var response = webClient.Get<T>(url, headers, null);
            if (!response.IsSuccessful)
                throw MakeNetworkError(response.ErrorException);

            return response;
        }

        internal static string Get(string url, string token, IWebClient webClient)
        {
            // Set headers
            var headers = new Dictionary<string, string>
            {
                { "Authorization", $"Zoho-authtoken {token}" },
                { "User-Agent", "ZohoVault/2.5.1 (Android 4.4.4; LGE/Nexus 5/19/2.5.1" },
                { "requestFrom", "vaultmobilenative" },
            };

            // GET
            var response = webClient.Get(url, headers, null);
            if (!response.IsSuccessful)
                throw MakeNetworkError(response.ErrorException);

            return response.Content;
        }

        class ResponseEnvelope<T>
        {
            public readonly Operation operation;
            public readonly T details;
        }

        struct Operation
        {
            public readonly string name;
            public readonly Result result;
        }

        struct Result
        {
            public readonly string status;
            public readonly string message;
        }

        internal static T GetJsonObject<T>(string url, string token, IWebClient webClient)
        {
            var response = Get<ResponseEnvelope<T>>(url, token, webClient).Data;
            if (response.operation.result.status != "success")
                throw MakeInvalidResponseFormat();

            return response.details;
        }

        internal static JToken GetJsonObject(string url, string token, IWebClient webClient)
        {
            JObject parsed;
            try
            {
                parsed = JObject.Parse(Get(url, token, webClient));
            }
            catch (JsonException e)
            {
                throw MakeInvalidResponse("Invalid JSON in response", e);
            }

            if (parsed.StringAtOrNull("operation/result/status") != "success")
                throw MakeInvalidResponseFormat();

            var details = parsed.AtOrNull("operation/details");
            if (details == null || details.Type != JTokenType.Object)
                throw MakeInvalidResponseFormat();

            return details;
        }

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
    }
}
