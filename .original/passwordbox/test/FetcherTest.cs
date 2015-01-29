// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Linq;
using Moq;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class FetcherTest
    {
        // Test data is generated with the PasswordBox JavaScript sources
        private const string Username = "username";
        private const string Password = "password";
        private const string PasswordHash = "bb5eeb368dd3d7ba5ab371c76ba5073e0a91f55697b81790bb34846d3e25f8e4";
        private const string LoginUrl = "https://api0.passwordbox.com/api/0/api_login.json";

        private static readonly NameValueCollection ExpectedLoginRequestValues = new NameValueCollection
            {
                {"member[email]", Username},
                {"member[password]", PasswordHash},
            };

        private const int ClientIterationCount = 500;
        private const int ServerIterationCount = 9498;

        private const string Salt = "1095d8447adfdba215ea3dfd7dbf029cc8cf09c6fade18c76a356c908f48175b";
        private const string EncryptedKey = "AAR6fDOLfXJKRxiYYhm4u/OgQw3tIWtPUFutlF55RgshUagCtR3WXiZGG52m" +
                                            "2RutxUrKcrJj7ZdTHVWukvYH2MveKbKuljwVv0zWnSwHqQSf0aRzJhyl0JWB";
        private static readonly byte[] Key = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562".DecodeHex();

        private static readonly string DerivationRulesJson = string.Format(
            @"{{""client_iterations"":""{0}"",""iterations"":""{1}""}}",
            ClientIterationCount,
            ServerIterationCount);

        private static readonly string ValidLoginResponseJson = string.Format(
            @"{{""salt"":""{0}"",""dr"":""{1}"",""k_kek"":""{2}""}}",
            Salt,
            DerivationRulesJson.Replace("\"", "\\\""), // Quotes have to be escaped before they are inserted into JSON
            EncryptedKey);

        [Test]
        public void Login_returns_valid_session()
        {
            var webClient = new Mock<IWebClient>();

            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(ValidLoginResponseJson.ToBytes());

            var session = Fetcher.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.UploadValues(
                    It.Is<string>(s => s == LoginUrl),
                    It.IsAny<NameValueCollection>()),
                Times.Once(),
                string.Format("Did not see a POST request made to the login URL ({0})", LoginUrl));

            webClient.Verify(
                x => x.UploadValues(
                    It.IsAny<string>(),
                    It.Is<NameValueCollection>(v => AreEqual(v, ExpectedLoginRequestValues))),
                Times.Once(),
                "Did not see a POST request made with the correct parameters");

            Assert.AreEqual("", session.Id);
            Assert.AreEqual(Key, session.Key);
        }

        [Test]
        public void ParseEncryptionKey()
        {
            var response = new Fetcher.LoginResponse(Salt, DerivationRulesJson, EncryptedKey);
            var key = Fetcher.ParseEncryptionKey(response, Password);
            Assert.AreEqual(Key, key);
        }

        [Test]
        [ExpectedException(typeof(Exception), ExpectedMessage = "Legacy user is not supported")]
        public void ParseEncryptionKey_throws_on_missing_salt()
        {
            var response = new Fetcher.LoginResponse(null, DerivationRulesJson, EncryptedKey);
            Fetcher.ParseEncryptionKey(response, Password);
        }

        [Test]
        [ExpectedException(typeof(Exception), ExpectedMessage = "Legacy user is not supported")]
        public void ParseEncryptionKey_throws_on_short_salt()
        {
            var response = new Fetcher.LoginResponse("too short", DerivationRulesJson, EncryptedKey);
            Fetcher.ParseEncryptionKey(response, Password);
        }

        [Test]
        public void ParseResponseJson_returns_correct_result()
        {
            var parsed = Fetcher.ParseResponseJson(ValidLoginResponseJson);
            Assert.AreEqual(Salt, parsed.Salt);
            Assert.AreEqual(DerivationRulesJson, parsed.DerivationRulesJson);
            Assert.AreEqual(EncryptedKey, parsed.EncryptedKey);
        }

        [Test]
        public void ParseDerivationRulesJson_returns_correct_result()
        {
            var parsed = Fetcher.ParseDerivationRulesJson(DerivationRulesJson);
            Assert.AreEqual(ClientIterationCount, parsed.ClientIterationCount);
            Assert.AreEqual(ServerIterationCount, parsed.ServerIterationCount);
        }

        //
        // Helpers
        //

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
