// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    class DuoTest
    {
        [Test]
        public void ParseSignature_returns_parts()
        {
            (var tx, var app) = Duo.ParseSignature("tx:app");

            Assert.That(tx, Is.EqualTo("tx"));
            Assert.That(app, Is.EqualTo("app"));
        }

        [Test]
        public void ParseSignature_throws_on_invalid_signature()
        {
            var cases = new[]
            {
                "",
                "tx",
                "tx:app:other"
            };

            foreach (var i in cases)
                Assert.That(() => Duo.ParseSignature(i),
                            Throws.InstanceOf<ClientException>().And.Message.Contains("signature is invalid"));
        }

        [Test]
        public void DownloadFrame_returns_html_document()
        {
            var http = JsonHttpClientTest.SetupPost("<html></html>");
            var html = Duo.DownloadFrame("host.com", "tx", http.Object);

            Assert.That(html.DocumentNode.InnerHtml, Is.EqualTo("<html></html>"));
        }

        [Test]
        public void DownloadFrame_throws_on_network_error()
        {
            var http = JsonHttpClientTest.SetupPostWithFailure();

            Assert.That(() => Duo.DownloadFrame("host.com", "tx", http.Object),
                        Throws.InstanceOf<ClientException>()
                            .And.Message.Contains("Network error")
                            .And.Property("Reason").EqualTo(ClientException.FailureReason.NetworkError));
        }
    }
}
