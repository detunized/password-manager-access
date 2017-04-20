// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Reflection;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class CryptoTest
    {
        [Test]
        public void HashPassword_returns_hash_string()
        {
            Assert.That(
                Crypto.HashPassword("username", "password"),
                Is.EqualTo("tk-v1-463d82f8e2378ed234ff98a84118636168b76a69cdac5fcb2b9594a0b18ad2ea"));
        }

        [Test]
        public void DecryptMasterKey_returns_key()
        {
            Assert.That(Crypto.DecryptMasterKey(MasterPassword, MasterKeySalt, EncryptedMasterKey),
                        Is.EqualTo(MasterKey));
        }

        // We don't test DecryptBase64 extensively as it's just a wrapper
        // around Decrypt which is well tested.
        [Test]
        public void DecryptBase64_returns_correct_result()
        {
            var decrypted = Crypto.DecryptBase64(Key, CiphertextBase64);
            Assert.That(decrypted, Is.EqualTo(Plaintext));
        }

        [Test]
        public void Decrypt_returns_correct_result()
        {
            var decrypted = Crypto.Decrypt(Key, Ciphertext);
            Assert.That(decrypted, Is.EqualTo(Plaintext));
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_input()
        {
            var decrypted = Crypto.Decrypt(Key, "".ToBytes());
            Assert.That(decrypted, Is.Empty);
        }

        [Test]
        public void Decrypt_uses_first_256_bits_of_key_only()
        {
            var key = Key.Concat("0102030405060708".DecodeHex()).ToArray();
            var decrypted = Crypto.Decrypt(key, Ciphertext);
            Assert.That(decrypted, Is.EqualTo(Plaintext));
        }

        public void Decrypt_throws_on_too_short_key()
        {
            Assert.That(() => Crypto.Decrypt(new byte[15], Ciphertext),
                        Throws.TypeOf<CryptoException>()
                            .And.Message.EqualTo("Encryption key should be at least 16 bytes long"));
        }

        public void Decrypt_throws_on_missing_format_byte()
        {
            Assert.That(() => Crypto.Decrypt(Key, "00".DecodeHex()),
                        Throws.TypeOf<CryptoException>()
                            .And.Message.EqualTo("Ciphertext is too short (version byte is missing)"));
        }

        [Test]
        public void Decrypt_throws_on_missing_iv()
        {
            Assert.That(() => Crypto.Decrypt(Key, "0004".DecodeHex()),
                        Throws.TypeOf<CryptoException>()
                            .And.Message.EqualTo("Ciphertext is too short (IV is missing)"));
        }

        [Test]
        public void Decrypt_throws_on_unsupported_version()
        {
            Assert.That(() => Crypto.Decrypt(Key, "0005".DecodeHex()),
                        Throws.TypeOf<CryptoException>()
                            .And.Message.EqualTo("Unsupported cipher format version (5)"));
        }

        // We don't test DecryptAes256Ccm extensively as it's well tested in SjclCcm.
        [Test]
        public void DecryptAes256Ccm_returns_plaintext()
        {
            var ciphertext = Ciphertext.Skip(18).ToArray();
            var iv = Ciphertext.Skip(2).Take(16).ToArray();

            Assert.That(Crypto.DecryptAes256Ccm(Key, ciphertext, iv), Is.EqualTo(Plaintext));
        }

        [Test]
        public void ParseClientToken_returns_otp_info()
        {
            var otp = Crypto.ParseClientToken(ClientToken);

            Assert.That(otp.Version, Is.EqualTo(3));
            Assert.That(otp.OtpAlgorithm, Is.EqualTo(1));
            Assert.That(otp.OtpLength, Is.EqualTo(0));
            Assert.That(otp.HashAlgorithm, Is.EqualTo(2));
            Assert.That(otp.TimeStep, Is.EqualTo(30));
            Assert.That(otp.StartTime, Is.EqualTo(0));
            Assert.That(otp.Suite, Is.EqualTo("OCRA-1:HOTP-SHA256-0:QA08".ToBytes()));
            Assert.That(otp.HmacSeed, Is.EqualTo("6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64()));
            Assert.That(otp.Iptmk, Is.EqualTo("HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64()));
        }

        [Test]
        public void ValidateOtpInfo_throws_on_invalid_value()
        {
            var otp = new Crypto.OtpInfo(version : 3,
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
                var clone = (Crypto.OtpInfo)otp.GetType()
                    .GetMethod("MemberwiseClone", BindingFlags.NonPublic | BindingFlags.Instance)
                    .Invoke(otp, null);
                clone.GetType().GetField(name).SetValue(clone, value);

                Assert.That(() => Crypto.ValidateOtpInfo(clone),
                            Throws.ArgumentException.And.Message.Contains(contains));
            };

            Assert.That(() => Crypto.ValidateOtpInfo(otp), Throws.Nothing);

            check("Version", 13, "version");
            check("OtpAlgorithm", 13, "algorithm");
            check("OtpLength", 13, "length");
            check("HashAlgorithm", 13, "hash");
            check("Suite", "invalid suite".ToBytes(), "suite");
            check("HmacSeed", "invalid hmac seed".ToBytes(), "HMAC length");
            check("Iptmk", "invalid iptmk".ToBytes(), "IPTMK length");
        }

        [Test]
        public void GenerateRandomOtpChallenge_returns_challenge()
        {
            var otp = Crypto.GenerateRandomOtpChallenge(OtpInfo);

            // It's not much to verify here as these things are random
            Assert.That(otp.Challenge.Length, Is.EqualTo(Crypto.ChallengeSize));
            Assert.That(otp.Signature.Length, Is.EqualTo(32));

            // We assume the test is running less than 10 seconds
            Assert.That((DateTime.UtcNow - otp.Timestamp).TotalSeconds, Is.LessThan(10));
        }

        [Test]
        public void Sha256_returns_hashed_message()
        {
            Assert.That(Crypto.Sha256("message"),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }

        [Test]
        public void Hmac_returns_hashed_message()
        {
            Assert.That(Crypto.Hmac("salt".ToBytes(), "message".ToBytes()),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        [Test]
        public void RandomBytes_returns_array_of_requested_size()
        {
            foreach (var size in new[] { 0, 1, 2, 3, 4, 15, 255, 1024, 1337 })
                Assert.That(Crypto.RandomBytes(size).Length, Is.EqualTo(size));
        }

        [Test]
        public void SignChallenge_returns_signature()
        {
            var challege = string.Join("", Enumerable.Repeat("0123456789abcdef", 8)).ToBytes();

            Assert.That(
                Crypto.SignChallenge(OtpInfo, challege, 1493456789),
                Is.EqualTo("x9vFwF7JWRvMGfckSAFr5PtHkqfo4AAw2YzzBlxFYDY=".Decode64()));
        }

        [Test]
        public void SignChallenge_throws_on_invalid_challenge()
        {
            foreach (var size in
                     new[] { 0, 1, 1024, 1337, Crypto.ChallengeSize - 1, Crypto.ChallengeSize + 1 })
            {
                var challenge = Enumerable.Repeat((byte)0, size).ToArray();
                Assert.That(() => Crypto.SignChallenge(OtpInfo, challenge, 1),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Challenge must be"));
            }
        }

        //
        // Data
        //

        private const string KeyHex = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562";
        private const string CiphertextBase64 = "AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==";
        private static readonly byte[] Key = KeyHex.DecodeHex();
        private static readonly byte[] Ciphertext = CiphertextBase64.Decode64();
        private static readonly byte[] Plaintext = "password".ToBytes();

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
        private static readonly Crypto.OtpInfo OtpInfo = new Crypto.OtpInfo(
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
