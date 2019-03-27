// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Test.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class DuoTest
    {
        [Fact]
        public void ParseSignature_returns_parts()
        {
            var parsed = Duo.ParseSignature("tx:app");

            Assert.Equal("tx", parsed.Tx);
            Assert.Equal("app", parsed.App);
        }

        [Fact]
        public void ParseSignature_throws_on_invalid_signature()
        {
            var cases = new[]
            {
                "",
                "tx",
                "tx:app:other"
            };

            foreach (var i in cases)
                Exceptions.AssertThrowsInternalError(() => Duo.ParseSignature(i), "signature is invalid");
        }

        [Fact]
        public void DownloadFrame_returns_html_document()
        {
            var http = JsonHttpClientTest.SetupPost("<html></html>");
            var html = Duo.DownloadFrame("host.com", "tx", http.Object);

            Assert.Equal("<html></html>", html.DocumentNode.InnerHtml);
        }

        [Fact]
        public void DownloadFrame_throws_on_network_error()
        {
            var http = JsonHttpClientTest.SetupPostWithFailure();

            Exceptions.AssertThrowsNetworkError(() => Duo.DownloadFrame("host.com", "tx", http.Object), "Network error");
        }
    }
}
