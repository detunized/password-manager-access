// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
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

        [Test]
        public void Step1_returns_WWW_Authenticate_header()
        {
            var http = SetupStep1();
            Assert.That(Client.Step1(Username, Nonce, http.Object), Is.EqualTo(Step1Header));
        }

        [Test]
        public void Step1_throws_on_missing_WWW_Authenticate_header()
        {
            var http = SetupStep1(null);
            Assert.That(() => Client.Step1(Username, Nonce, http.Object),
                        Throws.TypeOf<InvalidOperationException>());
        }

        //
        // Helpers
        //

        public static Mock<IHttpClient> MakeStep1()
        {
            var http = SetupStep1();
            Client.Step1(Username, Nonce, http.Object);
            return http;
        }

        public static Mock<IHttpClient> SetupStep1(string header = Step1Header)
        {
            var http = SetupPost(HttpStatusCode.Unauthorized,
                                 new Dictionary<string, string> {{"WWW-Authenticate", header}});
            return http;
        }

        // TODO: Could be removed
        private static Mock<IHttpClient> SetupPost(HttpStatusCode status)
        {
            return SetupPost(status, new Dictionary<string, string>());
        }

        private static Mock<IHttpClient> SetupPost(HttpStatusCode status,
                                                   Dictionary<string, string> headers)
        {
            var response = new HttpResponseMessage(status);
            foreach (var i in headers)
                response.Headers.Add(i.Key, i.Value);

            var http = new Mock<IHttpClient>();
            http
                .Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
                .Returns(response);

            return http;
        }

        //
        // Data
        //

        private const string Username = "lastpass.ruby@gmail.com";
        private const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";
        private const string Step1Header = "WWW-Authenticate-step1";
    }
}
