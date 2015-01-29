// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

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

            return new Session("");
        }

        internal static string ParseEncryptionKey(LoginResponse loginResponse, string password)
        {
            var salt = loginResponse.Salt;
            if (salt == null || salt.Length < 32)
                throw new Exception("Legacy user is not supported"); // TODO: Use custom exception!

            // TODO: Check for errors!
            var dr = ParseDerivationRulesJson(loginResponse.DerivationRulesJson);
            var kek = Crypto.ComputeKek(password, salt, dr);

            return Crypto.Decrypt(kek, loginResponse.EncryptedKey).ToUtf8();
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
            return ParseResponseJson<LoginResponse>(json);
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
            return ParseResponseJson<DerivationRules>(json);
        }

        internal static T ParseResponseJson<T>(string json)
        {
            var s = new DataContractJsonSerializer(typeof(T));
            using (var stream = new MemoryStream(json.ToBytes(), false))
                return (T)s.ReadObject(stream);
        }
    }
}
