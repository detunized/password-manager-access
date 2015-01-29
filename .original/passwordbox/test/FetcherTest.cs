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
        private struct KekTestCase
        {
            public KekTestCase(int clientIterationCount, int serverIterationCount, string expected)
            {
                ClientIterationCount = clientIterationCount;
                ServerIterationCount = serverIterationCount;
                Expected = expected;
            }

            public readonly int ClientIterationCount;
            public readonly int ServerIterationCount;
            public readonly string Expected;
        }

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
        private const string Key = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562";

        private static readonly string DerivationRulesJson = string.Format(
            @"{{""client_iterations"":""{0}"",""iterations"":""{1}""}}",
            ClientIterationCount,
            ServerIterationCount);

        private static readonly string ValidLoginResponseJson = string.Format(
            @"{{""salt"":""{0}"",""dr"":""{1}"",""k_kek"":""{2}""}}",
            Salt,
            DerivationRulesJson.Replace("\"", "\\\""), // Quotes have to be escaped before they are inserted into JSON
            EncryptedKey);

        // Test data is generated with the PasswordBox JavaScript sources
        private const string KekPassword = "password";
        private const string KekSalt = "salt";

        private static readonly KekTestCase[] KekTestData = new KekTestCase[]
        {
            new KekTestCase(0, 0, "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                                  "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef"),

            new KekTestCase(1,  0, "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                                   "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac"),

            new KekTestCase(0,  1, "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                                   "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef"),

            new KekTestCase(1,  1, "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                                   "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac"),

            new KekTestCase(10,  0, "76ea6ae400308d72ceb56f223a44a31a552bdf03598f5fd39387467b618ce245" +
                                    "ecb1877528ca94f3e9e720dfdbd9f85af68f13346c3f9dfaed7417a4ea2dbeba"),

            new KekTestCase(0, 10, "57ffc1876b96dab3f8d3daed9455547f3f7c692de3684d34ea27f7b36143e2d2" +
                                   "03480a01370ba30ea03f6b1cb8fe89db63f1adec34913a7def56e194ed1b0a6a"),

            new KekTestCase(13, 42, "3f64e210cb30e46672e74a6c63e73201183a4fec4279480df4163882dd4ac1b2" +
                                    "6fd1333ba819dfb4f97381b93c65ba6b768034019113470db0356206f1bb9708"),
        };

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
            Assert.AreEqual(DerivationRulesJson, parsed.DerivationRulesJson);
            Assert.AreEqual(EncryptedKey, parsed.EncryptedKey);
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
        public void ParseDerivationRulesJson_returns_correct_result()
        {
            var parsed = Fetcher.ParseDerivationRulesJson(DerivationRulesJson);
            Assert.AreEqual(ClientIterationCount, parsed.ClientIterationCount);
            Assert.AreEqual(ServerIterationCount, parsed.ServerIterationCount);
        }

        [Test]
        public void ComputeKek_returns_correct_result()
        {
            foreach (var i in KekTestData)
            {
                var kek = Fetcher.ComputeKek(
                    KekPassword,
                    KekSalt,
                    new Fetcher.DerivationRules(i.ClientIterationCount, i.ServerIterationCount));

                Assert.AreEqual(i.Expected, kek);
            }
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
