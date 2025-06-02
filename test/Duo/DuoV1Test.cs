// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using Shouldly;
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
            tx.ShouldBe("tx");
            app.ShouldBe("app");
        }

        [Theory]
        [InlineData("")]
        [InlineData("tx")]
        [InlineData("tx:app:other")]
        public void ParseSignature_throws_on_invalid_signature(string invalid)
        {
            // Act later
            Action act = () => DuoV1.ParseSignature(invalid);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldContain("signature is invalid");
        }

        [Fact]
        public async Task DownloadFrame_returns_html_document()
        {
            // Arrange
            var flow = new RestFlow().Post("<html></html>");

            // Act
            var html = await DuoV1.DownloadFrame("tx", flow, CancellationToken.None);

            // Assert
            html.DocumentNode.InnerHtml.ShouldBe("<html></html>");
        }

        [Fact]
        public async Task DownloadFrame_throws_on_network_error()
        {
            // Arrange
            var flow = new RestFlow().Post("", HttpStatusCode.BadRequest);

            // Act later
            var act = () => DuoV1.DownloadFrame("tx", flow, CancellationToken.None);

            // Assert
            var ex = await act.ShouldThrowAsync<InternalErrorException>();
            ex.Message.ShouldMatch("Duo: rest call to https://.* failed .*");
        }
    }
}
