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

        private const string Salt = "1095d8447adfdba215ea3dfd7dbf029cc8cf09c6fade18c76a356c908f48175b";
        private const string DerivationRules = @"{""client_iterations"": ""500"", ""iterations"": ""9498""}";
        private const string EncryptedKey = "AAR6fDOLfXJKRxiYYhm4u/OgQw3tIWtPUFutlF55RgshUagCtR3WXiZGG52m" +
                                            "2RutxUrKcrJj7ZdTHVWukvYH2MveKbKuljwVv0zWnSwHqQSf0aRzJhyl0JWB";

        private static readonly string ValidLoginResponseJson = string.Format(
            @"{{
                ""salt"":  ""{0}"",
                ""dr"":    ""{1}"",
                ""k_kek"": ""{2}""
            }}",
            Salt,
            DerivationRules.Replace("\"", "\\\""), // Quotes have to be escaped before they are inserted into JSON
            EncryptedKey);

        [Test]
        public void Login_returns_valid_session()
        {
            var webClient = new Mock<IWebClient>();
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

            Assert.NotNull(session);
            Assert.AreEqual("", session.Id);
        }

        [Test]
        public void ComputePasswordHash_returns_correct_result()
        {
            // Test data is generated with the PasswordBox JavaScript sources
            var hash = Fetcher.ComputePasswordHash(Username, Password);
            Assert.AreEqual(PasswordHash, hash);
        }

        [Test]
        public void HexSha1_returns_correct_result()
        {
            // Test data is from http://www.nsrl.nist.gov/testdata/
            var hash = Fetcher.Sha1Hex("abc");
            Assert.AreEqual("a9993e364706816aba3e25717850c26c9cd0d89d", hash);
        }

        [Test]
        public void ParseResponseJson_returns_correct_result()
        {
            var parsed = Fetcher.ParseResponseJson(ValidLoginResponseJson);
            Assert.AreEqual(Salt, parsed.Salt);
            Assert.AreEqual(DerivationRules, parsed.DerivationRulesJson);
            Assert.AreEqual(EncryptedKey, parsed.EncryptedKey);
        }

        [Test]
        public void ParseEncryptionKey()
        {
            var response = new Fetcher.LoginResponse(Salt, DerivationRules, EncryptedKey);
            var key = Fetcher.ParseEncryptionKey(response, Password);
            Assert.AreEqual("", key);
        }

        [Test]
        [ExpectedException(typeof(Exception), ExpectedMessage = "Legacy user is not supported")]
        public void ParseEncryptionKey_throws_on_missing_salt()
        {
            var response = new Fetcher.LoginResponse(null, DerivationRules, EncryptedKey);
            Fetcher.ParseEncryptionKey(response, Password);
        }

        [Test]
        [ExpectedException(typeof(Exception), ExpectedMessage = "Legacy user is not supported")]
        public void ParseEncryptionKey_throws_on_short_salt()
        {
            var response = new Fetcher.LoginResponse("too short", DerivationRules, EncryptedKey);
            Fetcher.ParseEncryptionKey(response, Password);
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
