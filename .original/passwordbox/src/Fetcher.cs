// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
            [DataMember(Name = "salt")]
            public readonly string Salt = null;

            [DataMember(Name = "dr")]
            public readonly string DerivationRulesJson = null;

            [DataMember(Name = "k_kek")]
            public readonly string EncryptedKey = null;
        }

        internal static LoginResponse ParseResponseJson(string json)
        {
            var s = new DataContractJsonSerializer(typeof(LoginResponse));
            using (var stream = new MemoryStream(json.ToBytes(), false))
                return (LoginResponse)s.ReadObject(stream);
        }
    }
}
