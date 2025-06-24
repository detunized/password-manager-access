// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Net;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class ClientTest : TestBase
    {
        [Fact]
        public async Task RequestNewAuthSession_makes_POST_request_and_returns_a_session()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post(GetFixture("sessions"))
                .ExpectUrl("/auth/v4/sessions");

            // Act
            var session = await Client.RequestNewAuthSession(rest, CancellationToken.None);

            // Assert
            session.Code.ShouldBe(1000);
            session.TokenType.ShouldBe("Bearer");
            session.AccessToken.ShouldBe("gx6unefgftd3dem4uaf2ajimi4l4cgjq");
            session.Id.ShouldBe("mbv6z4cpi4mseqh2wbljnrynlbr7lcqm");
        }

        [Fact]
        public async Task RequestNewAuthSession_fails_on_error()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }.Post("""{"Code": 1001, "Error": "Invalid credentials"}""", HttpStatusCode.BadRequest);

            // Act later
            var act = () => Client.RequestNewAuthSession(rest, CancellationToken.None);

            // Act/Assert
            var ex = await act.ShouldThrowAsync<InternalErrorException>();
            ex.Message.ShouldMatch("Request to '.*' failed with HTTP status BadRequest and error 1001: 'Invalid credentials'");
        }

        [Fact]
        public async Task RequestAuthInfo_makes_POST_request_and_returns_auth_info()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Post(GetFixture("auth-info"))
                .ExpectUrl("/auth/v4/info")
                .ExpectContent("""{"Username":"username","Intent":"Proton"}""");

            // Act
            var authInfo = await Client.RequestAuthInfo("username", rest, CancellationToken.None);

            // Assert
            authInfo.Code.ShouldBe(1000);
            authInfo.Modulus.ShouldStartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            authInfo.ServerEphemeral.ShouldStartWith("VEzZpI2z");
            authInfo.Version.ShouldBe(4);
            authInfo.Salt.ShouldBe("sNvZT3Qzr/0y5w==");
            authInfo.SrpSession.ShouldBe("b9383fa145662386c91b7c440c2a4720");
        }

        [Fact]
        public async Task RequestExtraAuthInfo_makes_GET_request_and_returns_SRP_data()
        {
            // Arrange
            var rest = new RestFlow { UseSystemJson = true }
                .Get(GetFixture("extra-auth-info"))
                .ExpectUrl("/pass/v1/user/srp/info?Username=username&Intent=Proton");

            // Act
            var srpData = await Client.RequestExtraAuthInfo("username", rest, CancellationToken.None);

            // Assert
            srpData.Modulus.ShouldStartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            srpData.ServerEphemeral.ShouldStartWith("cpOjTyrS");
            srpData.Version.ShouldBe(4);
            srpData.Salt.ShouldBe("Rbr+rLgHibg/aA==");
            srpData.SessionId.ShouldBe("0621fe3601bdf366283bf99837e891d2");
        }
    }
}
