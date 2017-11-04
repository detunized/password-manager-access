// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using Moq;
using NUnit.Framework;
using System.Net.Http;

namespace RoboForm.Test
{
    [TestFixture]
    public class ClientTest
    {
        [Test]
        public void Step1AuthorizationHeader_returns_header()
        {
            var expected = "SibAuth realm=\"RoboForm Online Server\",data=\"biwsbj1sYXN0cGFzcy" +
                           "5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZThSR3Npc2c=\"";
            var header = Client.Step1AuthorizationHeader(Username, Nonce);
            Assert.That(header, Is.EqualTo(expected));
        }

        [Test]
        public void Step1_makes_POST_request_to_specific_server()
        {
            MakeStep1().Verify(x => x.Post(
                It.Is<string>(s => s.StartsWith("https://online.roboform.com/")),
                It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step1_POST_request_url_contains_username()
        {
            MakeStep1().Verify(x => x.Post(It.Is<string>(s => s.Contains(Username)),
                                           It.IsAny<Dictionary<string, string>>()));
        }

        [Test]
        public void Step1_makes_POST_request_with_authorization_header_set()
        {
            MakeStep1().Verify(x => x.Post(
                It.IsAny<string>(),
                It.Is<Dictionary<string, string>>(
                    d => d.ContainsKey("Authorization") &&
                         d["Authorization"].StartsWith("SibAuth realm="))));
        }

        //
        // Helpers
        //

        public static Mock<IHttpClient> MakeStep1()
        {
            var http = SetupPost(HttpStatusCode.Unauthorized);
            Client.Step1(Username, Nonce, http.Object);
            return http;
        }

        private static Mock<IHttpClient> SetupPost(HttpStatusCode status)
        {
            var http = new Mock<IHttpClient>();
            http
                .Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
                .Returns(new HttpResponseMessage(status));

            return http;
        }

        //
        // Data
        //

        private const string Username = "lastpass.ruby@gmail.com";
        private const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";
    }
}
