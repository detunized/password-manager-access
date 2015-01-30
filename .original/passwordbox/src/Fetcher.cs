// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
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

            // TODO: Handle errors!
            var response = webClient.UploadValues("https://api0.passwordbox.com/api/0/api_login.json",
                                                  parameters);

            var parsedResponse = ParseResponseJson(response.ToUtf8());
            var key = ParseEncryptionKey(parsedResponse, password);
            var id = ExtractSessionId(webClient.ResponseHeaders["set-cookie"]);

            // TODO: Extract cookie!
            return new Session(id, key);
        }

        public static Account[] Fetch(Session session)
        {
            using (var webClient = new WebClient())
                return Fetch(session, webClient);
        }

        public static Account[] Fetch(Session session, IWebClient webClient)
        {
            // TODO: Figure out url-escaping. It seems the cookie already comes escaped.
            webClient.Headers.Add("Cookie", string.Format("_pwdbox_session={0}", session.Id));
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
