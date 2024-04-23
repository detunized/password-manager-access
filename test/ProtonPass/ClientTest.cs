// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class ClientTest: TestBase
    {
        [Fact]
        public async void RequestNewAuthSession_returns_a_session()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("sessions"));

            // Act
            var session = await Client.RequestNewAuthSession(flow, new CancellationTokenSource().Token);

            // Assert
            session.Code.Should().Be(1000);
            session.TokenType.Should().Be("Bearer");
            session.AccessToken.Should().Be("gx6unefgftd3dem4uaf2ajimi4l4cgjq");
            session.Id.Should().Be("mbv6z4cpi4mseqh2wbljnrynlbr7lcqm");
        }

        [Fact]
        public async void RequestNewAuthSession_makes_a_POST_request()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("sessions"))
                    .ExpectUrl("/auth/v4/sessions")
                    .ExpectContent("");

            // Act/assert
            await Client.RequestNewAuthSession(flow, new CancellationTokenSource().Token);
        }

        [Fact]
        public async void RequestNewAuthSession_fails_on_invalid_json()
        {
            // Arrange
            var flow = new RestFlow().Post("}{");

            // Act
            Func<Task> act = () => Client.RequestNewAuthSession(flow, new CancellationTokenSource().Token);

            // Assert
            await act.Should()
                .ThrowAsync<InternalErrorException>()
                .WithMessage("Failed to parse the response JSON");
        }

        [Fact]
        public async void RequestNewAuthSession_fails_on_error()
        {
            // Arrange
            var flow = new RestFlow().Post("{\"Code\": 1001, \"Error\": \"Invalid credentials\"}", HttpStatusCode.BadRequest);

            // Act
            Func<Task> act = () => Client.RequestNewAuthSession(flow, new CancellationTokenSource().Token);

            // Assert
            await act.Should()
                .ThrowAsync<InternalErrorException>()
                .WithMessage("Request to '' failed with HTTP status BadRequest and error 1001: 'Invalid credentials'");
        }

        [Fact]
        public async void RequestAuthInfo_returns_auth_info()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("auth-info"));

            // Act
            var authInfo = await Client.RequestAuthInfo("username", flow, new CancellationTokenSource().Token);

            // Assert
            authInfo.Code.Should().Be(1000);
            authInfo.Modulus.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            authInfo.ServerEphemeral.Should().StartWith("VEzZpI2z");
            authInfo.Version.Should().Be(4);
            authInfo.Salt.Should().Be("sNvZT3Qzr/0y5w==");
            authInfo.SrpSession.Should().Be("b9383fa145662386c91b7c440c2a4720");
        }

        [Fact]
        public async void RequestAuthInfo_makes_a_POST_request()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-info"))
                    .ExpectUrl("/auth/v4/info")
                    .ExpectContent("{\"Username\":\"username\",\"Intent\":\"Proton\"}");

            // Act/assert
            await Client.RequestAuthInfo("username", flow, new CancellationTokenSource().Token);
        }

    }
}
