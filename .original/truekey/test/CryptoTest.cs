// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
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
                     new[] {0, 1, 1024, 1337, Crypto.ChallengeSize - 1, Crypto.ChallengeSize + 1})
            {
                var challenge = Enumerable.Repeat((byte)0, size).ToArray();
                Assert.That(() => Crypto.SignChallenge(OtpInfo, challenge, 1),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Challenge must be"));
            }
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
        public void ToUnixSeconds_returns_number_of_seconds()
        {
            Assert.That(Crypto.ToUnixSeconds(new DateTime(2017, 4, 29, 9, 6, 29, DateTimeKind.Utc)),
                        Is.EqualTo(1493456789));
        }

        //
        // Data
        //

        // TODO: Remove copy paste
        private static readonly Remote.OtpInfo OtpInfo = new Remote.OtpInfo(
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
