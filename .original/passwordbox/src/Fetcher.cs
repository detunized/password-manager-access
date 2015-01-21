// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace PasswordBox
{
    class Fetcher
    {
        public static Session Login(string username, string password)
        {
            using (var webClient = new WebClient())
                return Login(username, password, webClient);
        }

        public static Session Login(string username, string password, IWebClient webClient)
        {
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
    }
}
