// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class DuoTest
    {
        [Fact]
        public void ParseSignature_returns_parts()
        {
            var (tx, app) = Duo.ParseSignature("tx:app");

            Assert.Equal("tx", tx);
            Assert.Equal("app", app);
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
            var flow = new RestFlow().Post("<html></html>");
            var html = Duo.DownloadFrame("tx", flow);

            Assert.Equal("<html></html>", html.DocumentNode.InnerHtml);
        }

        [Fact]
        public void DownloadFrame_throws_on_network_error()
        {
            var flow = new RestFlow().Post("", HttpStatusCode.BadRequest);

            Exceptions.AssertThrowsInternalError(() => Duo.DownloadFrame("tx", flow));
        }

        //
        // Data
        //

        private const string BaseUrl = "http://base.url";
    }
}
