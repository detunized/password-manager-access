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
            var http = JsonHttpClientTest.SetupPostWithFixture("verify-key-response");
            new Client(http.Object).VerifySessionKey(TestData.Session, TestData.SesionKey);
        }

        [Test]
        public void GetAccountInfo_works()
        {
            var http = JsonHttpClientTest.SetupGetWithFixture("get-account-info-response");
            new Client(http.Object).GetAccountInfo(TestData.SesionKey);
        }
    }
}
