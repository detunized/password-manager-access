// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Reflection;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class UtilTest
    {
        [Fact]
        public void HashPassword_returns_hash_string()
        {
            Assert.Equal("tk-v1-463d82f8e2378ed234ff98a84118636168b76a69cdac5fcb2b9594a0b18ad2ea",
                         Util.HashPassword("username", "password"));
        }

        [Fact]
        public void DecryptMasterKey_returns_key()
        {
            Assert.Equal(MasterKey, Util.DecryptMasterKey(MasterPassword, MasterKeySalt, EncryptedMasterKey));
        }

        [Fact]
        public void Decrypt_returns_correct_result()
        {
            var decrypted = Util.Decrypt(Key, Ciphertext);
            Assert.Equal(Plaintext, decrypted);
        }

        [Fact]
        public void Decrypt_returns_empty_on_empty_input()
        {
            var decrypted = Util.Decrypt(Key, "".ToBytes());
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Decrypt_uses_first_256_bits_of_key_only()
        {
            var key = Key.Concat("0102030405060708".DecodeHex()).ToArray();
            var decrypted = Util.Decrypt(key, Ciphertext);
            Assert.Equal(Plaintext, decrypted);
        }

        [Fact]
        public void Decrypt_throws_on_too_short_key()
        {
            Exceptions.AssertThrowsInternalError(() => Util.Decrypt(new byte[15], Ciphertext),
                                                 "Encryption key should be at least 16 bytes long");
        }

        [Fact]
        public void Decrypt_throws_on_missing_format_byte()
        {
            Exceptions.AssertThrowsInternalError(() => Util.Decrypt(Key, "00".DecodeHex()),
                                                 "Ciphertext is too short (version byte is missing)");
        }

        [Fact]
        public void Decrypt_throws_on_missing_iv()
        {
            Exceptions.AssertThrowsInternalError(() => Util.Decrypt(Key, "0004".DecodeHex()),
                                                 "Ciphertext is too short (IV is missing)");
        }

        [Fact]
        public void Decrypt_throws_on_unsupported_version()
        {
            Exceptions.AssertThrowsInternalError(() => Util.Decrypt(Key, "0005".DecodeHex()),
                                                 "Unsupported cipher format version (5)");
        }

        // We don't test DecryptAes256Ccm extensively as it's well tested in SjclCcm.
        [Fact]
        public void DecryptAes256Ccm_returns_plaintext()
        {
            var ciphertext = Ciphertext.Skip(18).ToArray();
            var iv = Ciphertext.Skip(2).Take(16).ToArray();

            Assert.Equal(Plaintext, Util.DecryptAes256Ccm(Key, ciphertext, iv));
        }

        [Fact]
        public void ParseClientToken_returns_otp_info()
        {
            var otp = Util.ParseClientToken(ClientToken);

            Assert.Equal(3, otp.Version);
            Assert.Equal(1, otp.OtpAlgorithm);
            Assert.Equal(0, otp.OtpLength);
            Assert.Equal(2, otp.HashAlgorithm);
            Assert.Equal(30, otp.TimeStep);
            Assert.Equal(0U, otp.StartTime);
            Assert.Equal("OCRA-1:HOTP-SHA256-0:QA08".ToBytes(), otp.Suite);
            Assert.Equal("6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(), otp.HmacSeed);
            Assert.Equal("HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64(), otp.Iptmk);
        }

        [Fact]
        public void ValidateOtpInfo_throws_on_invalid_value()
        {
            var otp = new Util.OtpInfo(version : 3,
                                         otpAlgorithm : 1,
                                         otpLength : 0,
                                         hashAlgorithm : 2,
                                         timeStep : 30,
                                         startTime : 0,
                                         suite : "OCRA-1:HOTP-SHA256-0:QA08".ToBytes(),
                                         hmacSeed : "6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(),
                                         iptmk : "HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64());

            Action<string, object, string> check = (name, value, contains) =>
            {
                // This is a bit ugly but gets the job done.
                // We clone the valid object and modify one field to something invalid.
                var clone = (Util.OtpInfo)otp.GetType()
                    .GetMethod("MemberwiseClone", BindingFlags.NonPublic | BindingFlags.Instance)
                    .Invoke(otp, null);
                clone.GetType().GetField(name).SetValue(clone, value);

                Exceptions.AssertThrowsInternalError(() => Util.ValidateOtpInfo(clone), contains);
            };

            // Doesn't throw
            Util.ValidateOtpInfo(otp);

            check("Version", 13, "version");
            check("OtpAlgorithm", 13, "algorithm");
            check("OtpLength", 13, "length");
            check("HashAlgorithm", 13, "hash");
            check("Suite", "invalid suite".ToBytes(), "suite");
            check("HmacSeed", "invalid hmac seed".ToBytes(), "HMAC length");
            check("Iptmk", "invalid iptmk".ToBytes(), "IPTMK length");
        }

        [Fact]
        public void GenerateRandomOtpChallenge_returns_challenge()
        {
            var otp = Util.GenerateRandomOtpChallenge(OtpInfo);

            // It's not much to verify here as these things are random
            Assert.Equal(Util.ChallengeSize, otp.Challenge.Length);
            Assert.Equal(32, otp.Signature.Length);

            // We assume the test is running less than 10 seconds
            Assert.True((DateTime.UtcNow - otp.Timestamp).TotalSeconds < 10);
        }

        [Fact]
        public void SignChallenge_returns_signature()
        {
            var challenge = string.Join("", Enumerable.Repeat("0123456789abcdef", 8)).ToBytes();

            Assert.Equal("x9vFwF7JWRvMGfckSAFr5PtHkqfo4AAw2YzzBlxFYDY=".Decode64(),
                         Util.SignChallenge(OtpInfo, challenge, 1493456789));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(1024)]
        [InlineData(1337)]
        [InlineData(Util.ChallengeSize - 1)]
        [InlineData(Util.ChallengeSize + 1)]
        public void SignChallenge_throws_on_invalid_challenge(int size)
        {
            //var challenge = Enumerable.Repeat((byte)0, size).ToArray();
            Exceptions.AssertThrowsInternalError(() => Util.SignChallenge(OtpInfo, new byte[size], 1),
                                                 "Challenge must be");
        }

        //
        // Data
        //

        private const string KeyHex = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562";
        private const string CiphertextBase64 = "AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==";
        private static readonly byte[] Key = KeyHex.DecodeHex();
        private static readonly byte[] Ciphertext = CiphertextBase64.Decode64();
        private static readonly byte[] Plaintext = "password".ToBytes();

        // TODO: Remove copy paste
        private const string MasterPassword = "Password123";
        private const string MasterKeySaltHex = "845864cf3692189757f5f276b37c2981bdceefea04905" +
                                                "699685ad0541c4f9092";
        private const string EncryptedMasterKeyBase64 = "AARZxaQ5EeiK9GlqAkz+BzTwb1cO+b8yMN+SC" +
                                                        "t3bzQJO+Fyf4TnlA83Mbl1KrMI09iOd9VQJJl" +
                                                        "u4ivWMwCYhMB6Mw3LOoyS/2UjqmCnxAUqo6MT" +
                                                        "SnptgjlWO";
        private const string MasterKeyBase64 = "EWQ91qe9SB9KSqp5L6PiZSTg/CD5phR6LekyBanDyIY=";

        private static readonly byte[] MasterKeySalt = MasterKeySaltHex.DecodeHex();
        private static readonly byte[] EncryptedMasterKey = EncryptedMasterKeyBase64.Decode64();
        private static readonly byte[] MasterKey = MasterKeyBase64.Decode64();

        // TODO: Remove copy paste
        private const string ClientToken = "AQCmAwEAAh4AAAAAWMajHQAAGU9DUkEtMTpIT1RQLVNIQTI1Ni" +
                                           "0wOlFBMDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAIOiRfItpCTOkvq0ZfV2+GgvP" +
                                           "83aF9SrTBfOuabZfcQr9AAAAAAgAIBwWTZpUTIn493Us/Jwczr" +
                                           "K6O0+LH8FRidFaZkJ2AlTu";

        // TODO: Remove copy paste
        private static readonly Util.OtpInfo OtpInfo = new Util.OtpInfo(
            version: 3,
            otpAlgorithm: 1,
            otpLength: 0,
            hashAlgorithm: 2,
            timeStep: 30,
            startTime: 0,
            suite: "OCRA-1:HOTP-SHA256-0:QA08".ToBytes(),
            hmacSeed: "6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(),
            iptmk: "HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64());
    }
}
