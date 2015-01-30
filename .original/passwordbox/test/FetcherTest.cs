// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
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

        private const string SessionId = "BAh7C0kiD3Nlc3Npb25faWQGOgZFVEkiJThjYjM2MDM5YTk5ZWQzMj" +
                                         "JmM2UzYjI1NjU4NWE4M2JmBjsAVEkiC3RhZ2dlZAY7AEZsKwevvspU" +
                                         "SSIbd2FyZGVuLnVzZXIubWVtYmVyLmtleQY7AFRbB1sGaQOvxXhJIi" +
                                         "IkMmEkMTAkUk5NaHo3QlE1a2dRck5OWXFVMDEyLgY7AFRJIh93YXJk" +
                                         "ZW4udXNlci5tZW1iZXIuc2Vzc2lvbgY7AFR7BkkiFGxhc3RfcmVxdW" +
                                         "VzdF9hdAY7AFRJdToJVGltZQ23wxzAmy02Nwk6DW5hbm9fbnVtaQL4" +
                                         "AToNbmFub19kZW5pBjoNc3VibWljcm8iB1BAOgl6b25lSSIIVVRDBj" +
                                         "sAVEkiEHNfdGltZXN0YW1wBjsARmwrB6%2B%2BylRJIhBfY3NyZl90" +
                                         "b2tlbgY7AEZJIjEwcC90aGtYT3ZjdmUwazZsV0ZkdkFmNTZPaVFsdn" +
                                         "lqK1RSYmVmOUUxRmFVPQY7AEY%3D--634da8b44072734f07b02aea" +
                                         "c047b02a05a7b6bc";

        private static readonly string SetCookie = string.Format(
            "__cfduid=dd095cad151de65f366b14bab1cb5f3c71422573230; expires=Fri, 29-Jan-16 23:13:" +
            "50 GMT; path=/; domain=.passwordbox.com; HttpOnly,lang=en_US; domain=.passwordbox.c" +
            "om; path=/; expires=Fri, 29-Jan-2016 23:13:51 GMT,_pwdbox_session={0}; domain=.pass" +
            "wordbox.com; path=/; secure; HttpOnly", SessionId);

        private const string FetchResponseJson =
            "[{\"id\":15839376,\"member_id\":7914927,\"name\":\"example.com\",\"url\":\"http://e" +
            "xample.com\",\"login\":\"username\",\"password\":null,\"note\":{},\"created_at\":\"" +
            "2014-12-12T19:25:45-05:00\",\"updated_at\":\"2015-01-17T19:27:58-05:00\",\"type\":\"" +
            "Other\",\"virtual_password\":null,\"fields\":null,\"domain\":\"example.com\",\"deta" +
            "ils\":\"\",\"password_k\":\"AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==\",\"se" +
            "ttings\":\"{\\\"autologin\\\":\\\"1\\\",\\\"password_reprompt\\\":\\\"0\\\",\\\"sub" +
            "domain_only\\\":\\\"0\\\"}\",\"memo_k\":null},{\"id\":15845973,\"member_id\":791492" +
            "7,\"name\":\"dude\",\"url\":\"https://dude.com\",\"login\":\"jeffrey.lebowski\",\"p" +
            "assword\":null,\"note\":{},\"created_at\":\"2014-12-13T06:25:32-05:00\",\"updated_a" +
            "t\":\"2015-01-17T19:44:03-05:00\",\"type\":\"Other\",\"virtual_password\":null,\"fi" +
            "elds\":null,\"domain\":\"dude.com\",\"details\":null,\"password_k\":\"AASkzvBholmWA" +
            "Q1hktcv91xhy3jL36DnUie3LRQpPvKabQwO\",\"settings\":\"{\\\"autologin\\\":\\\"1\\\",\\" +
            "\"password_reprompt\\\":\\\"0\\\",\\\"subdomain_only\\\":\\\"0\\\"}\",\"memo_k\":\"" +
            "AATXMJp/fQisb66TB9kEH6J2rDTxF7SL+xKO9nXfiCMH67W+ooeHaA==\"}]";

        private static readonly Account[] Accounts =
        {
            new Account(
                      id: "15839376",
                    name: "example.com",
                     url: "http://example.com",
                username: "username",
                password: "password",
                   notes: ""),

            new Account(
                      id: "15845973",
                    name: "dude",
                     url: "https://dude.com",
                username: "jeffrey.lebowski",
                password: "logjammin'",
                   notes: "Get a new rug!"),
        };

        [Test]
        public void Login_returns_valid_session()
        {
            var webClient = new Mock<IWebClient>();

            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(ValidLoginResponseJson.ToBytes());

            webClient
                .SetupGet(x => x.ResponseHeaders)
                .Returns(() => {
                    var headers = new WebHeaderCollection();
                    headers.Add("set-cookie", SetCookie);
                    return headers;
                });

            var session = Fetcher.Login(Username, Password, webClient.Object);

            // TODO: Split this test in two or more! It's checking at least two different things.

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

            Assert.AreEqual(SessionId, session.Id);
            Assert.AreEqual(Key, session.Key);
        }

        [Test]
        public void Fetch_returns_valid_accounts()
        {
            var webClient = new Mock<IWebClient>();

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(FetchResponseJson.ToBytes());

            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            // TODO: Split this test in two or more! It's checking at least two different things.

            var accounts = Fetcher.Fetch(new Session(SessionId, Key), webClient.Object);

            Assert.AreEqual(Accounts.Length, accounts.Length);
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

        [Test]
        public void ExtractSessionId_returns_correct_result()
        {
            Assert.AreEqual(SessionId, Fetcher.ExtractSessionId(SetCookie));
        }

        [Test]
        [ExpectedException(typeof(Exception), ExpectedMessage = "Unsupported cookie format")]
        public void ExtractSessionId_throws_on_invalid_cookies()
        {
            Assert.AreEqual(SessionId, Fetcher.ExtractSessionId(""));
        }

        [Test]
        public void ParseFetchResponseJson_returns_correct_result()
        {
            var parsed = Fetcher.ParseFetchResponseJson(FetchResponseJson);

            Assert.AreEqual(Accounts.Length, parsed.Length);
            for (var i = 0; i < parsed.Length; ++i)
            {
                var a = Accounts[i];
                var p = parsed[i];

                // Only check these, the rest is encrypted
                // TODO: Make a complete test!
                Assert.AreEqual(a.Id, p.Id);
                Assert.AreEqual(a.Name, p.Name);
                Assert.AreEqual(a.Username, p.Username);
                Assert.AreEqual(a.Url, p.Url);
            }
        }

        [Test]
        public void DecryptAccounts_returns_correct_result()
        {
            var accounts = Fetcher.DecryptAccounts(Fetcher.ParseFetchResponseJson(FetchResponseJson), Key);

            Assert.AreEqual(Accounts.Length, accounts.Length);
            for (var i = 0; i < accounts.Length; ++i)
            {
                var e = Accounts[i];
                var a = accounts[i];

                Assert.AreEqual(e.Id, a.Id);
                Assert.AreEqual(e.Name, a.Name);
                Assert.AreEqual(e.Username, a.Username);
                Assert.AreEqual(e.Password, a.Password);
                Assert.AreEqual(e.Url, a.Url);
                Assert.AreEqual(e.Notes, a.Notes);
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
