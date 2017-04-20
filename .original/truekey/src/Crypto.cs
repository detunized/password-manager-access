// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
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

        public static byte[] DecryptMasterKey(string password, byte[] salt, byte[] encryptedKey)
        {
            var key = Pbkdf2.Generate(password, salt, 10000, 32);
            return Decrypt(key, encryptedKey).ToUtf8().DecodeHex();
        }

        // TODO: Remove this
        public static byte[] DecryptBase64(byte[] key, string encrypted)
        {
            return Decrypt(key, encrypted.Decode64());
        }

        public static byte[] Decrypt(byte[] key, byte[] encrypted)
        {
            if (key.Length < 16)
                throw new CryptoException("Encryption key should be at least 16 bytes long");

            // Use only first 256 bits
            if (key.Length > 32)
                key = key.Take(32).ToArray();

            if (encrypted.Length == 0)
                return new byte[0];

            if (encrypted.Length < 2)
                throw new CryptoException("Ciphertext is too short (version byte is missing)");

            // Version byte is at offset 1.
            // We only support version 4 which seems to be the current.
            var version = encrypted[1];
            if (version != 4)
                throw new CryptoException(string.Format("Unsupported cipher format version ({0})",
                                                        version));

            if (encrypted.Length < 18)
                throw new CryptoException("Ciphertext is too short (IV is missing)");

            // Split encrypted into IV and cipher
            var ciphertext = encrypted.Skip(18).ToArray();
            var iv = encrypted.Skip(2).Take(16).ToArray();

            return DecryptAes256Ccm(key, ciphertext, iv);
        }

        // TODO: See how this could be optimized to reuse AES object w/o recreating it every time!
        public static byte[] DecryptAes256Ccm(byte[] key, byte[] ciphertext, byte[] iv)
        {
            var aes = new SjclAes(key);
            return SjclCcm.Decrypt(aes, ciphertext, iv, new byte[0], 8);
        }

        // Contains all the stuff that is needed to generate and verify
        // OTP (one time password) time based challenges.
        public class OtpInfo
        {
            public readonly int Version;
            public readonly int OtpAlgorithm;
            public readonly int OtpLength;
            public readonly int HashAlgorithm;
            public readonly int TimeStep;
            public readonly uint StartTime;
            public readonly byte[] Suite;
            public readonly byte[] HmacSeed;
            public readonly byte[] Iptmk;

            public OtpInfo(int version,
                           int otpAlgorithm,
                           int otpLength,
                           int hashAlgorithm,
                           int timeStep,
                           uint startTime,
                           byte[] suite,
                           byte[] hmacSeed,
                           byte[] iptmk)
            {
                Version = version;
                OtpAlgorithm = otpAlgorithm;
                OtpLength = otpLength;
                HashAlgorithm = hashAlgorithm;
                TimeStep = timeStep;
                StartTime = startTime;
                Suite = suite;
                HmacSeed = hmacSeed;
                Iptmk = iptmk;
            }
        }

        // Parses clientToken field returned by the server. It contains encoded
        // OCRA/OPT/RFC 6287 information. This is used later on to sign messages.
        public static OtpInfo ParseClientToken(string encodedToken)
        {
            using (var s = new MemoryStream(encodedToken.Decode64()))
            using (var r = new BinaryReader(s))
            {
                var tokenType = r.ReadByte();
                var tokenLength = r.ReadUInt16BigEndian();
                var token = r.ReadBytes(tokenLength);
                var iptmkTag = r.ReadByte();
                var iptmkLength = r.ReadUInt16BigEndian();
                var iptmk = r.ReadBytes(iptmkLength);

                using (var ts = new MemoryStream(token))
                using (var tr = new BinaryReader(ts))
                {
                    var version = tr.ReadByte();
                    var otpAlgorithm = tr.ReadByte();
                    var otpLength = tr.ReadByte();
                    var hashAlgorithm = tr.ReadByte();
                    var timeStep = tr.ReadByte();
                    var startTime = tr.ReadUInt32BigEndian();
                    var serverTime = tr.ReadUInt32BigEndian();
                    var wysOption = tr.ReadByte();
                    var suiteLength = tr.ReadUInt16BigEndian();
                    var suite = tr.ReadBytes(suiteLength);

                    ts.Position = 128;
                    var hmacSeedLength = tr.ReadUInt16BigEndian();
                    var hmacSeed = tr.ReadBytes(hmacSeedLength);

                    return new OtpInfo(version : version,
                                       otpAlgorithm : otpAlgorithm,
                                       otpLength : otpLength,
                                       hashAlgorithm : hashAlgorithm,
                                       timeStep : timeStep,
                                       startTime : startTime,
                                       suite : suite,
                                       hmacSeed : hmacSeed,
                                       iptmk : iptmk);
                }
            }
        }

        // Checks that the OTP info is something we can work with. The Chrome
        // extension also supports only this subset. They don't validate as much,
        // just assume the values are what they expect.
        public static void ValidateOtpInfo(OtpInfo otp)
        {
            Action<object, object, string> throwError = (actual, expected, name) =>
            {
                throw new ArgumentException(
                    String.Format("Invalid OTP {0} (expected {1}, got {2})",
                                  name,
                                  expected,
                                  actual));
            };

            Action<int, int, string> verify = (actual, expected, name) =>
            {
                if (actual != expected)
                    throwError(actual, expected, name);
            };

            verify(otp.Version, 3, "version");
            verify(otp.OtpAlgorithm, 1, "algorithm");
            verify(otp.OtpLength, 0, "length");
            verify(otp.HashAlgorithm, 2, "hash");
            verify(otp.HmacSeed.Length, 32, "HMAC length");
            verify(otp.Iptmk.Length, 32, "IPTMK length");

            const string suite = "OCRA-1:HOTP-SHA256-0:QA08";
            if (!otp.Suite.SequenceEqual(suite.ToBytes()))
                throwError(otp.Suite, suite, "suite");
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

        public static OtpChallenge GenerateRandomOtpChallenge(OtpInfo otp)
        {
            var challenge = RandomBytes(ChallengeSize);
            var time = DateTime.UtcNow;
            return new OtpChallenge(challenge,
                                    time,
                                    SignChallenge(otp, challenge, time.UnixSeconds()));
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

        internal static byte[] SignChallenge(OtpInfo otp, byte[] challenge, uint unixSeconds)
        {
            if (challenge.Length != ChallengeSize)
                throw new ArgumentOutOfRangeException(
                    "challenge",
                    challenge.Length,
                    String.Format("Challenge must be {0} bytes long", ChallengeSize));

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
