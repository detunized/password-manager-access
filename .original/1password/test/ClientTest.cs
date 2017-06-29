// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void VerifySessionKey_works()
        {
            var sessionKey = new AesKey(
                TestData.SessionId,
                "1c45a129b9e96b2f2eae330e8fd3c2dbb9dbe71b696d19823f3fa031b3218aad".DecodeHex());

            var http = JsonHttpClientTest.SetupPostWithFixture("verify-key-response");
            new Client(http.Object).VerifySessionKey(TestData.Session, sessionKey);
        }

        [Test]
        public void GetAccountInfo_works()
        {
            var sessionKey = new AesKey(
                TestData.SessionId,
                "1c45a129b9e96b2f2eae330e8fd3c2dbb9dbe71b696d19823f3fa031b3218aad".DecodeHex());

            var http = JsonHttpClientTest.SetupGetWithFixture("get-account-info-response");
            new Client(http.Object).GetAccountInfo(sessionKey);
        }
    }
}
