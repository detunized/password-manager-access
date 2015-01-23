// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace PasswordBox
{
    public class Fetcher
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
                    {"member[password]", ComputePasswordHash(username, password)},
                };

            var response = webClient.UploadValues("https://api0.passwordbox.com/api/0/api_login.json",
                                                  parameters);

            return new Session("");
        }

        internal static string ComputePasswordHash(string username, string password)
        {
            var salt = Sha1Hex(username);
            return Pbkdf2.GenerateSha256(password, salt, 10000, 256 / 8).ToHex();
        }

        internal static string Sha1Hex(string text)
        {
            using (var sha = new SHA1Managed())
                return sha.ComputeHash(text.ToBytes()).ToHex();
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

        internal static LoginResponse ParseResponseJson(string json)
        {
            var s = new DataContractJsonSerializer(typeof(LoginResponse));
            using (var stream = new MemoryStream(json.ToBytes(), false))
                return (LoginResponse)s.ReadObject(stream);
        }

        internal static DerivationRules ParseDerivationRulesJson(string json)
        {
            var s = new DataContractJsonSerializer(typeof(DerivationRules));
            using (var stream = new MemoryStream(json.ToBytes(), false))
                return (DerivationRules)s.ReadObject(stream);
        }

        internal static string ParseEncryptionKey(LoginResponse loginResponse, string password)
        {
            var salt = loginResponse.Salt;
            if (salt == null || salt.Length < 32)
                throw new Exception("Legacy user is not supported"); // TODO: Use custom exception!

            return "";
        }

        // Computes the KEK (key encryption key) which is used to encrypt/decrypt the actual key
        // with which all the data is encrypted.
        internal static string ComputeKek(string password, string salt, DerivationRules derivationRules)
        {
            var client = Math.Max(0, derivationRules.ClientIterationCount);
            var server = Math.Max(1, derivationRules.ServerIterationCount);

            var step1 = Pbkdf2Sha1(password, salt, 1, 512);
            var step2 = Pbkdf2Sha256(step1, salt, client, 512);
            var step3 = Pbkdf2Sha256(step2, salt, server, 256);
            var step4 = Pbkdf2Sha1(step3 + password, salt, 1, 512);

            return step4;
        }

        // TODO: Try to remove this copy-paste
        internal static string Pbkdf2Sha1(string password, string salt, int iterationCount, int bits)
        {
            if (iterationCount <= 0)
                return password;

            return Pbkdf2.GenerateSha1(password, salt, iterationCount, bits / 8).ToHex();
        }

        // TODO: Try to remove this copy-paste
        internal static string Pbkdf2Sha256(string password, string salt, int iterationCount, int bits)
        {
            if (iterationCount <= 0)
                return password;

            return Pbkdf2.GenerateSha256(password, salt, iterationCount, bits / 8).ToHex();
        }
    }
}
