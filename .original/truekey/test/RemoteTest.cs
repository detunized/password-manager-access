// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
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

        //
        // Data
        //

        private const string ClientToken = "AQCmAwEAAh4AAAAAWMajHQAAGU9DUkEtMTpIT1RQLVNIQTI1Ni" +
                                           "0wOlFBMDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAIOiRfItpCTOkvq0ZfV2+GgvP" +
                                           "83aF9SrTBfOuabZfcQr9AAAAAAgAIBwWTZpUTIn493Us/Jwczr" +
                                           "K6O0+LH8FRidFaZkJ2AlTu";

        //
        // Helpers
        //

        private static Mock<IHttpClient> SetupPost(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static Mock<IHttpClient> SetupPostWithFixture(string name)
        {
            return SetupPost(File.ReadAllText(string.Format("Fixtures/{0}.json", name)));
        }
    }
}
