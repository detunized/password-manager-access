// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using MockHttp;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass;
using Xunit;
using static PasswordManagerAccess.Test.TestUtil;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class ClientTest : TestBase
    {
        [Fact]
        public async Task RequestNewAuthSession_returns_a_session()
        {
            // Arrange
            var rest = Serve(GetFixture("sessions"));

            // Act
            var session = await Client.RequestNewAuthSession(rest, MakeToken());

            // Assert
            session.Code.Should().Be(1000);
            session.TokenType.Should().Be("Bearer");
            session.AccessToken.Should().Be("gx6unefgftd3dem4uaf2ajimi4l4cgjq");
            session.Id.Should().Be("mbv6z4cpi4mseqh2wbljnrynlbr7lcqm");
        }

        [Fact]
        public async Task RequestNewAuthSession_makes_POST_request()
        {
            // Arrange
            var mockHttp = new MockHttpHandler();
            mockHttp.When(w => w.Method("POST").RequestUri("*/auth/v4/sessions").WithoutBody()).Respond(w => w.JsonText(GetFixture("sessions")));

            // Act
            await Swallow(() => Client.RequestNewAuthSession(mockHttp.ToClient(), MakeToken()));

            mockHttp.VerifyAll();
            mockHttp.VerifyNoOtherRequests();
        }

        [Fact]
        public async Task RequestNewAuthSession_fails_on_error()
        {
            // Arrange
            var rest = Serve("{\"Code\": 1001, \"Error\": \"Invalid credentials\"}", HttpStatusCode.BadRequest);

            // Act
            Func<Task> act = () => Client.RequestNewAuthSession(rest, MakeToken());

            // Assert
            await act.Should()
                .ThrowAsync<InternalErrorException>()
                .WithMessage("Request to '*' failed with HTTP status BadRequest and error 1001: 'Invalid credentials'");
        }

        [Fact]
        public async Task RequestAuthInfo_returns_auth_info()
        {
            // Arrange
            var rest = Serve(GetFixture("auth-info"));

            // Act
            var authInfo = await Client.RequestAuthInfo("username", rest, MakeToken());

            // Assert
            authInfo.Code.Should().Be(1000);
            authInfo.Modulus.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            authInfo.ServerEphemeral.Should().StartWith("VEzZpI2z");
            authInfo.Version.Should().Be(4);
            authInfo.Salt.Should().Be("sNvZT3Qzr/0y5w==");
            authInfo.SrpSession.Should().Be("b9383fa145662386c91b7c440c2a4720");
        }

        [Fact]
        public async Task RequestAuthInfo_makes_POST_request()
        {
            // Arrange
            var mockHttp = new MockHttpHandler();
            mockHttp
                .When(w => w.Method("POST").RequestUri("*/auth/v4/info").JsonText("{\"Username\":\"username\",\"Intent\":\"Proton\"}"))
                .Respond(w => w.JsonText(GetFixture("auth-info")));

            // Act/assert
            await Swallow(() => Client.RequestAuthInfo("username", mockHttp.ToClient(), MakeToken()));

            mockHttp.VerifyAll();
            mockHttp.VerifyNoOtherRequests();
        }

        [Fact]
        public async Task RequestExtraAuthInfo_returns_SRP_data()
        {
            // Arrange
            var rest = Serve(GetFixture("extra-auth-info"));

            // Act
            var srpData = await Client.RequestExtraAuthInfo("username", rest, MakeToken());

            // Assert
            srpData.Modulus.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            srpData.ServerEphemeral.Should().StartWith("cpOjTyrS");
            srpData.Version.Should().Be(4);
            srpData.Salt.Should().Be("Rbr+rLgHibg/aA==");
            srpData.SessionId.Should().Be("0621fe3601bdf366283bf99837e891d2");
        }

        [Fact]
        public async Task RequestExtraAuthInfo_makes_GET_request()
        {
            // Arrange
            var mockHttp = new MockHttpHandler();
            mockHttp
                .When(w => w.Method("GET").RequestUri("*/pass/v1/user/srp/info").JsonText("{\"Username\":\"username\",\"Intent\":\"Proton\"}"))
                .Respond(w => w.JsonText(GetFixture("extra-auth-info")));

            // Act/assert
            await Swallow(() => Client.RequestExtraAuthInfo("username", mockHttp.ToClient(), MakeToken()));

            mockHttp.VerifyAll();
            mockHttp.VerifyNoOtherRequests();
        }

        //
        // Helpers
        //

        private class TestAsyncUi : IAsyncUi
        {
            public Task<IAsyncUi.CaptchaResult> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken) =>
                Task.FromResult(new IAsyncUi.CaptchaResult(true, "ok-human-verification-token"));

            public Task<IAsyncUi.PasscodeResult> ProvideExtraPassword(int attempt, CancellationToken cancellationToken) =>
                Task.FromResult(new IAsyncUi.PasscodeResult("extra-password"));

            public Task<IAsyncUi.PasscodeResult> ProvideGoogleAuthPasscode(int attempt, CancellationToken cancellationToken) =>
                Task.FromResult(new IAsyncUi.PasscodeResult("123456"));
        }

        private static IAsyncUi GetAsyncUi()
        {
            return new TestAsyncUi();
        }

        private static IAsyncSecureStorage GetAsyncStorage()
        {
            return new MemoryStorage(
                new()
                {
                    ["session-id"] = "session-id",
                    ["access-token"] = "access-token",
                    ["refresh-token"] = "refresh-token",
                }
            );
        }
    }
}
