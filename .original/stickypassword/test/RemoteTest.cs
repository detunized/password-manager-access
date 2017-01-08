// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Moq;
using NUnit.Framework;
using RestSharp;

namespace StickyPassword.Test
{
    [TestFixture]
    class RemoteTest
    {
        public const string Username = "lebowski";
        public const string Password = "logjammin";
        public const string DeviceId = "ringer";
        public static readonly DateTime Timestamp = new DateTime(1998, 3, 6);
        public const string Token = "2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=";
        public const string Response = @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?><SpcResponse xmlns=""http://www.stickypassword.com/cb/clientapi/schema/v2""><Status>13</Status><GetCrpTokenResponse><CrpToken>2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=</CrpToken></GetCrpTokenResponse></SpcResponse>";

        [Test]
        public void GetEncryptedToken_sets_api_base_url()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.VerifySet(x => x.BaseUrl = It.Is<Uri>(
                u => u.AbsoluteUri.Contains("stickypassword.com/SPCClient")));
        }

        [Test]
        public void GetEncryptedToken_sets_user_agent_with_device_id()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.VerifySet(x => x.UserAgent = It.Is<string>(s => s.Contains(DeviceId)));
        }

        [Test]
        public void GetEncryptedToken_makes_post_request_to_specific_end_point()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.Verify(x => x.Execute(It.Is<IRestRequest>(
                r => r.Method == Method.POST && r.Resource == "GetCrpToken")));
        }

        [Test]
        public void GetEncryptedToken_date_header_is_set()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            var expectedDate = Timestamp.ToUniversalTime().ToString("R");
            client.Verify(x => x.Execute(It.Is<IRestRequest>(
                r => r.Parameters.Exists(
                    p => p.Type == ParameterType.HttpHeader
                        && p.Name == "Date"
                        && p.Value.ToString() == expectedDate))));
        }

        [Test]
        public void GetEncryptedToken_returns_response()
        {
            var client = SetupClient();

            Assert.That(
                Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object),
                Is.EqualTo(Token));
        }

        //
        // Helpers
        //

        private static Mock<IRestClient> SetupClient(string response = Response)
        {
            var mock = new Mock<IRestClient>();
            mock
                .Setup(x => x.Execute(It.IsAny<IRestRequest>()))
                .Returns(SetupResponse(response).Object);
            return mock;
        }

        private static Mock<IRestResponse> SetupResponse(string response)
        {
            var mock = new Mock<IRestResponse>();
            mock.Setup(x => x.Content).Returns(response);
            return mock;
        }
    }
}
