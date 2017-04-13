// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Security.Cryptography;

namespace TrueKey
{
    internal static class Crypto
    {
        public static string HashPassword(string username, string password)
        {
            var salt = Sha256(username);
            var derived = Pbkdf2.Generate(password, salt, 10000, 32);
            return "tk-v1-" + derived.ToHex();
        }

        //
        // internal
        //

        internal static byte[] Sha256(string data)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(data.ToBytes());
        }

        internal static byte[] Hmac(byte[] salt, byte[] message)
        {
            using (var hmac = new HMACSHA256 {Key = salt})
                return hmac.ComputeHash(message);
        }

        internal static byte[] SignChallenge(Remote.OtpInfo otp, byte[] challenge, uint unixSeconds)
        {
            if (challenge.Length != 128)
                throw new ArgumentOutOfRangeException("challenge",
                                                      challenge.Length,
                                                      "Challenge must be 128 bytes long");

            using (var s = new MemoryStream(1024))
            {
                s.Write(otp.Suite, 0, otp.Suite.Length);
                s.WriteByte(0);
                s.Write(challenge, 0, challenge.Length);

                var z = BitConverter.GetBytes((UInt32)0);
                s.Write(z, 0, z.Length);

                var time = (unixSeconds - otp.StartTime) / otp.TimeStep;
                var t = BitConverter.GetBytes((UInt32)time);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(t);
                s.Write(t, 0, t.Length);

                return Hmac(otp.HmacSeed, s.ToArray());
            }
        }
    }
}
