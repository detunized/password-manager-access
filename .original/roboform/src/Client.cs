// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace RoboForm
{
    public static class Client
    {
        public static void Login(string username, string password, IHttpClient http)
        {
            var nonce = "-DeHRrZjC8DZ_0e8RGsisg";
            var header = Step1(username, nonce, http);
            var authInfo = ParseAuthInfo(header);
            var response = Step2(username, password, nonce, authInfo, http);
        }

        internal static string Step1(string username, string nonce, IHttpClient http)
        {
            // TODO: Wrap in using when done
            var response = http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step1AuthorizationHeader(username, nonce)}
            });

            if (response.StatusCode != HttpStatusCode.Unauthorized)
                throw new InvalidOperationException("Expected 401"); // TODO: Custom exception

            var header = GetHeader(response, "WWW-Authenticate");
            if (string.IsNullOrWhiteSpace(header))
                throw new InvalidOperationException("WWW-Authenticate header expected"); // TODO: Custom exception

            return header;
        }

        internal static string Step2(string username,
                                     string password,
                                     string nonce,
                                     AuthInfo authInfo,
                                     IHttpClient http)
        {
            var response = http.Post(LoginUrl(username), new Dictionary<string, string>
            {
                {"Authorization", Step2AuthorizationHeader(username, password, nonce, authInfo)}
            });

            var cookie = GetHeader(response, "Set-Cookie");
            if (string.IsNullOrWhiteSpace(cookie))
                throw new InvalidOperationException("Auth cookie expected"); // TODO: Custom exception

            return cookie;
        }

        internal static string Step1AuthorizationHeader(string username, string nonce)
        {
            var data = string.Format("n,,n={0},r={1}", username.EncodeUri(), nonce);
            return string.Format("SibAuth realm=\"RoboForm Online Server\",data=\"{0}\"",
                                 data.ToBase64());
        }

        internal static string Step2AuthorizationHeader(string username,
                                                        string password,
                                                        string nonce,
                                                        AuthInfo authInfo)
        {
            var clientKey = Crypto.ComputeClientKey(password, authInfo);
            var clientHash = Crypto.Sha256(clientKey);

            var hashingMaterial = string.Format("n={0},r={1},{2},c=biws,r={3}",
                                                username.EncodeUri(),
                                                nonce,
                                                authInfo.Data,
                                                authInfo.Nonce);

            var hashed = Crypto.Hmac(clientHash, hashingMaterial.ToBytes());
            var proof = clientKey.Zip(hashed, (a, b) => (byte)(a ^ b)).ToArray();
            var data = string.Format("c=biws,r={0},p={1}", authInfo.Nonce, proof.ToBase64());

            return string.Format("SibAuth sid=\"{0}\",data=\"{1}\"", authInfo.Sid, data.ToBase64());
        }

        // TODO: Move out to separate file
        internal class AuthInfo
        {
            public AuthInfo(string sid,
                            string data,
                            string nonce,
                            byte[] salt,
                            int iterationCount,
                            bool isMd5)
            {
                Sid = sid;
                Data = data;
                Nonce = nonce;
                Salt = salt;
                IterationCount = iterationCount;
                IsMd5 = isMd5;
            }

            public readonly string Sid;
            public readonly string Data;
            public readonly string Nonce;
            public readonly byte[] Salt;
            public readonly int IterationCount;
            public readonly bool IsMd5;
        }

        internal static AuthInfo ParseAuthInfo(string encoded)
        {
            try
            {
                var splitHeader = encoded.Split(' ');
                if (splitHeader.Length < 2)
                    throw new InvalidOperationException("Invalid auth info format");

                var realm = splitHeader[0];
                var parameters = splitHeader[1];

                if (realm != "SibAuth")
                    throw new InvalidOperationException(
                        string.Format("Invalid auth info realm '{0}'", realm));

                var parsedParameters = parameters
                    .Split(',')
                    .Select(ParseAuthInfoQuotedParam)
                    .ToDictionary(i => i.Key, i => i.Value);

                var sid = parsedParameters["sid"];
                var data = parsedParameters["data"].Decode64().ToUtf8();

                var parsedData = data
                    .Split(',')
                    .Select(ParseAuthInfoParam)
                    .ToDictionary(i => i.Key, i => i.Value);

                var isMd5 = false;
                if (parsedData.ContainsKey("o"))
                    isMd5 = parsedData["o"].Contains("pwdMD5");

                return new AuthInfo(sid: sid,
                                    data: data,
                                    nonce: parsedData["r"],
                                    salt: parsedData["s"].Decode64(),
                                    iterationCount: int.Parse(parsedData["i"]),
                                    isMd5: isMd5);
            }
            catch (KeyNotFoundException e)
            {
                throw new InvalidOperationException("Invalid auth info format", e);
            }
        }

        // Parse name=value
        internal static KeyValuePair<string, string> ParseAuthInfoParam(string encoded)
        {
            return ParseAuthInfoParam(encoded, ParamRegex);
        }

        // Parse name="value"
        internal static KeyValuePair<string, string> ParseAuthInfoQuotedParam(string encoded)
        {
            return ParseAuthInfoParam(encoded, QuotedParamRegex);
        }

        internal static KeyValuePair<string, string> ParseAuthInfoParam(string encoded, Regex regex)
        {
            var m = regex.Match(encoded);
            if (!m.Success || m.Groups.Count < 3)
                throw new InvalidOperationException("Invalid auth info parameter format");

            return new KeyValuePair<string, string>(m.Groups[1].Value, m.Groups[2].Value);
        }

        internal static string LoginUrl(string username)
        {
            return string.Format("https://online.roboform.com/rf-api/{0}?login",
                                 username.EncodeUri());
        }

        internal static string GetHeader(HttpResponseMessage response, string name)
        {
            IEnumerable<string> header;
            if (response.Headers.TryGetValues(name, out header))
                return header.FirstOrDefault();

            return null;
        }

        private static readonly Regex ParamRegex = new Regex(@"^(\w+)\=(.*?)$");
        private static readonly Regex QuotedParamRegex = new Regex(@"^(\w+)\=""(.*?)""$");
    }
}
