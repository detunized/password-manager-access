// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net;
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

        [Theory]
        [InlineData("")]
        [InlineData("tx")]
        [InlineData("tx:app:other")]
        public void ParseSignature_throws_on_invalid_signature(string invalid)
        {
            Exceptions.AssertThrowsInternalError(() => Duo.ParseSignature(invalid), "signature is invalid");
        }

        [Fact]
        public void DownloadFrame_returns_html_document()
        {
            var rest = RestClientTest.Serve("<html></html>", BaseUrl);
            var html = Duo.DownloadFrame("tx", rest);

            Assert.Equal("<html></html>", html.DocumentNode.InnerHtml);
        }

        [Fact]
        public void DownloadFrame_throws_on_network_error()
        {
            var rest = RestClientTest.Fail(HttpStatusCode.BadRequest, BaseUrl);

            Exceptions.AssertThrowsInternalError(() => Duo.DownloadFrame("tx", rest));
        }

        //
        // Data
        //

        private const string BaseUrl = "http://base.url";
    }
}
