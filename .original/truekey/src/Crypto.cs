// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Security.Cryptography;

namespace TrueKey
{
    internal static class Crypto
    {
        public const int ChallengeSize = 128;

        public static string HashPassword(string username, string password)
        {
            var salt = Sha256(username);
            var derived = Pbkdf2.Generate(password, salt, 10000, 32);
            return "tk-v1-" + derived.ToHex();
        }

        public class OtpChallenge
        {
            public readonly byte[] Challenge;
            public readonly DateTime Timestamp;
            public readonly byte[] Signature;

            public OtpChallenge(byte[] challenge, DateTime timestamp, byte[] signature)
            {
                Challenge = challenge;
                Timestamp = timestamp;
                Signature = signature;
            }
        }

        public static OtpChallenge GenerateRandomOtpChallenge(Remote.OtpInfo otp)
        {
            var challenge = RandomBytes(ChallengeSize);
            var time = DateTime.UtcNow;
            return new OtpChallenge(challenge,
                                    time,
                                    SignChallenge(otp, challenge, ToUnixSeconds(time)));
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

        internal static byte[] RandomBytes(int size)
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[size];
                random.GetBytes(bytes);
                return bytes;
            }
        }

        // TODO: Move to extensions of DateTime
        internal static uint ToUnixSeconds(DateTime time)
        {
            const long secondsSinceEpoch = 62135596800;
            long seconds = time.ToUniversalTime().Ticks / TimeSpan.TicksPerSecond - secondsSinceEpoch;
            // TODO: This will stop working on January 19, 2038 03:14:07. Fix ASAP!
            return (uint)seconds;
        }

        internal static byte[] SignChallenge(Remote.OtpInfo otp, byte[] challenge, uint unixSeconds)
        {
            if (challenge.Length != ChallengeSize)
                throw new ArgumentOutOfRangeException(
                    "challenge",
                    challenge.Length,
                    string.Format("Challenge must be {0} bytes long", ChallengeSize));

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
