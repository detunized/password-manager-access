// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace PasswordBox
{
    public static class Fetcher
    {
        public static Session Login(string username, string password)
        {
            using (var webClient = new WebClient())
                return Login(username, password, webClient);
        }

        public static Session Login(string username, string password, IWebClient webClient)
        {
            var parameters = new NameValueCollection
            {
                {"member[email]", username},
                {"member[password]", Crypto.ComputePasswordHash(username, password)},
            };

            try
            {
                var response = webClient.UploadValues("https://api0.passwordbox.com/api/0/api_login.json",
                                                      parameters);
                var parsedResponse = ParseResponseJson(response.ToUtf8());
                var key = ParseEncryptionKey(parsedResponse, password);
                var id = ExtractSessionId(webClient.ResponseHeaders[HttpResponseHeader.SetCookie]);

                return new Session(id, key);
            }
            catch (WebException e)
            {
                string response;
                using (var s = new StreamReader(e.Response.GetResponseStream(), Encoding.UTF8))
                    response = s.ReadToEnd();

                var parsedResponse = ErrorResponse.FromJson(response);

                LoginException.FailureReason reason;
                var message = parsedResponse.Message;

                switch (parsedResponse.ErrorCode)
                {
                case "invalid_credentials":
                    reason = LoginException.FailureReason.InvalidUsername;
                    message = "Invalid username";
                    break;
                default:
                    if (string.IsNullOrEmpty(message))
                    {
                        reason = LoginException.FailureReason.Unknown;
                        message = "Unknown Reason";
                    }
                    else
                    {
                        reason = LoginException.FailureReason.Other;
                    }
                    break;
                }

                throw new LoginException(reason, message);
            }
        }

        public static void Logout(Session session)
        {
            using (var webClient = new WebClient())
                Logout(session, webClient);
        }

        public static void Logout(Session session, IWebClient webClient)
        {
            webClient.Headers.Add(HttpRequestHeader.Cookie, string.Format("_pwdbox_session={0}", session.Id));
            var response = webClient.DownloadData("https://api0.passwordbox.com/api/0/api_logout.json");

            var parsedResponse = ParseLogoutResponseJson(response.ToUtf8());
            if (parsedResponse.Message != "Good bye")
                throw new Exception("Logout failed"); // TODO: Use custom exception!
        }

        public static Account[] Fetch(Session session)
        {
            using (var webClient = new WebClient())
                return Fetch(session, webClient);
        }

        public static Account[] Fetch(Session session, IWebClient webClient)
        {
            // TODO: Figure out url-escaping. It seems the cookie already comes escaped.
            webClient.Headers.Add(HttpRequestHeader.Cookie, string.Format("_pwdbox_session={0}", session.Id));
            var response = webClient.DownloadData("https://api0.passwordbox.com/api/0/assets");

            // TODO: Handle errors!

            var encryptedAccounts = ParseFetchResponseJson(response.ToUtf8());
            return DecryptAccounts(encryptedAccounts, session.Key);
        }

        internal static byte[] ParseEncryptionKey(LoginResponse loginResponse, string password)
        {
            var salt = loginResponse.Salt;
            if (salt == null || salt.Length < 32)
                throw new Exception("Legacy user is not supported"); // TODO: Use custom exception!

            // TODO: Check for errors!
            var dr = ParseDerivationRulesJson(loginResponse.DerivationRulesJson);
            var kek = Crypto.ComputeKek(password, salt, dr);

            return Crypto.Decrypt(kek, loginResponse.EncryptedKey).ToUtf8().DecodeHex();
        }

        [DataContract]
        internal class ErrorResponse
        {
            public static ErrorResponse FromJson(string json)
            {
                return ParseJson<ErrorResponse>(json);
            }

            public ErrorResponse(string errorType, string httpStatus, string errorCode, string message)
            {
                ErrorType = errorType;
                HttpStatus = httpStatus;
                ErrorCode = errorCode;
                Message = message;
            }

            [DataMember(Name = "error_type")]
            public readonly string ErrorType = null;

            [DataMember(Name = "http_status")]
            public readonly string HttpStatus = null;

            [DataMember(Name = "error_code")]
            public readonly string ErrorCode = null;

            [DataMember(Name = "message")]
            public readonly string Message = null;
        }

        [DataContract]
        internal class LoginResponse
        {
            public LoginResponse(string salt, string derivationRulesJson, string encryptedKey)
            {
                Salt = salt;
                DerivationRulesJson = derivationRulesJson;
                EncryptedKey = encryptedKey;
            }

            [DataMember(Name = "salt")]
            public readonly string Salt = null;

            [DataMember(Name = "dr")]
            public readonly string DerivationRulesJson = null;

            [DataMember(Name = "k_kek")]
            public readonly string EncryptedKey = null;
        }

        internal static LoginResponse ParseResponseJson(string json)
        {
            return ParseJson<LoginResponse>(json);
        }

        [DataContract]
        internal class DerivationRules
        {
            public DerivationRules(int clientIterationCount, int serverIterationCount)
            {
                ClientIterationCount = clientIterationCount;
                ServerIterationCount = serverIterationCount;
            }

            [DataMember(Name = "client_iterations")]
            public readonly int ClientIterationCount = 0;

            [DataMember(Name = "iterations")]
            public readonly int ServerIterationCount = 1;
        }

        internal static DerivationRules ParseDerivationRulesJson(string json)
        {
            return ParseJson<DerivationRules>(json);
        }

        internal static T ParseJson<T>(string json)
        {
            var s = new DataContractJsonSerializer(typeof(T));
            using (var stream = new MemoryStream(json.ToBytes(), false))
                return (T)s.ReadObject(stream);
        }

        internal static string ExtractSessionId(string cookies)
        {
            var match = Regex.Match(cookies, "_pwdbox_session=(.*?);");
            if (!match.Success)
                throw new Exception("Unsupported cookie format"); // TODO: Use custom exception!

            return match.Groups[1].Value;
        }

        [DataContract]
        internal class LogoutResponse
        {
            [DataMember(Name = "message")]
            public readonly string Message;
        }

        internal static LogoutResponse ParseLogoutResponseJson(string json)
        {
            return ParseJson<LogoutResponse>(json);
        }

        [DataContract]
        internal class EncryptedAccount
        {
            [DataMember(Name = "id")]
            public readonly string Id = null;

            [DataMember(Name = "name")]
            public readonly string Name = null;

            [DataMember(Name = "url")]
            public readonly string Url = null;

            [DataMember(Name = "login")]
            public readonly string Username = null;

            [DataMember(Name = "password_k")]
            public readonly string Password = null;

            [DataMember(Name = "memo_k")]
            public readonly string Notes = null;
        }

        internal static EncryptedAccount[] ParseFetchResponseJson(string json)
        {
            return ParseJson<EncryptedAccount[]>(json);
        }

        internal static Account[] DecryptAccounts(EncryptedAccount[] encryptedAccounts, byte[] key)
        {
            // TODO: Figure out how not to reconvert key to hex all the time!
            // TODO: Figure out how to reuse AES object that is created in Crypto.Decypt!

            return encryptedAccounts.Select(i => new Account(
                      id: i.Id ?? "",
                    name: i.Name ?? "",
                username: i.Username ?? "",
                password: Crypto.Decrypt(key.ToHex(), i.Password ?? "").ToUtf8(),
                     url: i.Url ?? "",
                   notes: Crypto.Decrypt(key.ToHex(), i.Notes ?? "").ToUtf8()
            )).ToArray();
        }
    }
}
