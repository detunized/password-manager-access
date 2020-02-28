// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.RoboForm
{
    internal class AuthInfo
    {
        public readonly string Sid;
        public readonly string Data;
        public readonly string Nonce;
        public readonly byte[] Salt;
        public readonly int IterationCount;
        public readonly bool IsMd5;

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

        public static AuthInfo Parse(string encoded)
        {
            try
            {
                var splitHeader = encoded.Split(' ');
                if (splitHeader.Length < 2)
                    throw MakeError("Invalid auth info format");

                var realm = splitHeader[0];
                var parameters = splitHeader[1];

                if (realm != "SibAuth")
                    throw MakeError(string.Format("Invalid auth info realm '{0}'", realm));

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
                                    iterationCount: Int32.Parse(parsedData["i"]),
                                    isMd5: isMd5);
            }
            catch (KeyNotFoundException)
            {
                throw MakeError("Invalid auth info format");
            }
        }

        //
        // Internal
        //

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
                throw MakeError("Invalid auth info parameter format");

            return new KeyValuePair<string, string>(m.Groups[1].Value, m.Groups[2].Value);
        }

        //
        // Private
        //

        private static InternalErrorException MakeError(string message)
        {
            return new InternalErrorException(message);
        }

        private static readonly Regex ParamRegex = new Regex(@"^(\w+)\=(.*?)$");
        private static readonly Regex QuotedParamRegex = new Regex(@"^(\w+)\=""(.*?)""$");
    }
}
