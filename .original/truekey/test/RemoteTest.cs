// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Moq;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class RemoteTest
    {
        [Test]
        public void RegisetNewDevice_returns_device_info()
        {
            var client = SetupPostWithFixture("register-new-device-response");
            var result = Remote.RegisetNewDevice("truekey-sharp", client.Object);

            Assert.That(result.Token, Is.StringStarting("AQCmAwEA"));
            Assert.That(result.Id, Is.StringStarting("d871347b"));
        }

        [Test]
        public void ParseClientToken_returns_otp_info()
        {
            var otp = Remote.ParseClientToken(ClientToken);

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
            var otp = new Remote.OtpInfo(version: 3,
                                         otpAlgorithm: 1,
                                         otpLength: 0,
                                         hashAlgorithm: 2,
                                         timeStep: 30,
                                         startTime: 0,
                                         suite: "OCRA-1:HOTP-SHA256-0:QA08".ToBytes(),
                                         hmacSeed: "6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(),
                                         iptmk: "HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64());

            Action<string, object, string> check = (name, value, contains) =>
            {
                // This is a bit ugly but gets the job done.
                // We clone the valid object and modify one field to something invalid.
                var clone = (Remote.OtpInfo)otp.GetType()
                    .GetMethod("MemberwiseClone", BindingFlags.NonPublic | BindingFlags.Instance)
                    .Invoke(otp, null);
                clone.GetType().GetField(name).SetValue(clone, value);

                Assert.That(() => Remote.ValidateOtpInfo(clone),
                            Throws.ArgumentException.And.Message.Contains(contains));
            };

            Assert.That(() => Remote.ValidateOtpInfo(otp), Throws.Nothing);

            check("Version", 13, "version");
            check("OtpAlgorithm", 13, "algorithm");
            check("OtpLength", 13, "length");
            check("HashAlgorithm", 13, "hash");
            check("Suite", "invalid suite".ToBytes(), "suite");
            check("HmacSeed", "invalid hmac seed".ToBytes(), "HMAC length");
            check("Iptmk", "invalid iptmk".ToBytes(), "IPTMK length");
        }

        [Test]
        public void AuthStep1_returns_transaction_id()
        {
            var client = SetupPostWithFixture("auth-step1-response");
            var result = Remote.AuthStep1(ClientInfo, client.Object);

            Assert.That(result, Is.EqualTo("6cdfcd43-065c-43a1-aa7a-017de98eefd0"));
        }

        //
        // Data
        //

        private const string Username = "username@example.com";
        private const string DeviceName = "truekey-sharp";

        private const string ClientToken = "AQCmAwEAAh4AAAAAWMajHQAAGU9DUkEtMTpIT1RQLVNIQTI1Ni" +
                                           "0wOlFBMDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAIOiRfItpCTOkvq0ZfV2+GgvP" +
                                           "83aF9SrTBfOuabZfcQr9AAAAAAgAIBwWTZpUTIn493Us/Jwczr" +
                                           "K6O0+LH8FRidFaZkJ2AlTu";

        private const string DeviceId = "d871347bd0a3e7af61f60f511bc7de5e944c5c778705649d4aa8d" +
                                        "c77bcd21489412894";

        private static readonly Remote.DeviceInfo DeviceInfo = new Remote.DeviceInfo(
            token: ClientToken,
            id: DeviceId);

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

        private static readonly Remote.ClientInfo ClientInfo = new Remote.ClientInfo(
            username: Username,
            name: DeviceName,
            deviceInfo: DeviceInfo,
            otpInfo: OtpInfo);

        //
        // Helpers
        //

        private static Mock<IHttpClient> SetupPost(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, object>>()))
                .Returns(response);
            return mock;
        }

        private static Mock<IHttpClient> SetupPostWithFixture(string name)
        {
            return SetupPost(File.ReadAllText(string.Format("Fixtures/{0}.json", name)));
        }
    }
}
