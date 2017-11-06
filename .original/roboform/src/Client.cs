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
            var header = Step1(username, "-DeHRrZjC8DZ_0e8RGsisg", http);
            var authInfo = ParseAuthInfo(header);
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
            if (header == null)
                throw new InvalidOperationException("WWW-Authenticate header expected"); // TODO: Custom exception

            return header;
        }

        internal static string Step1AuthorizationHeader(string username, string nonce)
        {
            var data = string.Format("n,,n={0},r={1}", username.EncodeUri(), nonce);
            return string.Format("SibAuth realm=\"RoboForm Online Server\",data=\"{0}\"",
                                 data.ToBase64());
        }

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
            var splitHeader = encoded.Split(' ');
            if (splitHeader.Length < 2)
                throw new InvalidOperationException("Invalid format");

            var realm = splitHeader[0];
            var parameters = splitHeader[1];

            if (realm != "SibAuth")
                throw new InvalidOperationException(string.Format("Invalid realm '{0}'", realm));

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
                throw new InvalidOperationException("Invalid format");

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
