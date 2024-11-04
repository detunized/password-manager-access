// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using Xunit;

namespace PasswordManagerAccess.Test.Duo
{
    public class DuoV1Test
    {
        [Fact]
        public void ParseSignature_returns_parts()
        {
            // Arrange/Act
            var (tx, app) = DuoV1.ParseSignature("tx:app");

            // Assert
            tx.Should().Be("tx");
            app.Should().Be("app");
        }

        [Theory]
        [InlineData("")]
        [InlineData("tx")]
        [InlineData("tx:app:other")]
        public void ParseSignature_throws_on_invalid_signature(string invalid)
        {
            // Arrange/Act
            var act = () => DuoV1.ParseSignature(invalid);

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage("*signature is invalid*");
        }

        [Fact]
        public async Task DownloadFrame_returns_html_document()
        {
            // Arrange
            var flow = new RestFlow().Post("<html></html>");

            // Act
            var html = await DuoV1.DownloadFrame("tx", flow, CancellationToken.None);

            // Assert
            html.DocumentNode.InnerHtml.Should().Be("<html></html>");
        }

        [Fact]
        public async Task DownloadFrame_throws_on_network_error()
        {
            // Arrange
            var flow = new RestFlow().Post("", HttpStatusCode.BadRequest);

            // Act
            var act = () => DuoV1.DownloadFrame("tx", flow, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>();
        }

        //
        // Data
        //

        private const string BaseUrl = "http://base.url";
    }
}
