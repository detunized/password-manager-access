// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword;

public partial class ClientTest
{
    //
    // IsSsoAccount
    //

    [Theory]
    [InlineData(true, "OIDC")]
    [InlineData(true, "PASSWORD+SK", "OIDC")]
    [InlineData(false, "PASSWORD+SK")]
    [InlineData(false)]
    public async Task IsSsoAccount_returns_expected_result(bool expected, params string[] authMethodTypes)
    {
        // Arrange
        var flow = new RestFlow { UseSystemJson = true }
            .Post(MakeLoginInfoResponse(authMethodTypes))
            .ExpectUrl("v2/auth/methods")
            .ToRestClient(SsoApiUrl);

        // Act
        var result = await Client.IsSsoAccount("user@example.com", flow, CancellationToken.None);

        // Assert
        result.ShouldBe(expected);
    }

    //
    // LogIn (IRestTransport overload)
    //

    [Fact]
    public async Task LogIn_checks_SSO_on_default_domain_not_custom_domain()
    {
        // Arrange
        var credentials = new Credentials
        {
            Username = TestData.Username,
            Password = TestData.Password,
            AccountKey = TestData.AccountKey,
            DeviceUuid = TestData.DeviceUuid,
            Domain = "custom-team.1password.com",
        };
        var flow = new RestFlow { UseSystemJson = true }
            // 1. SSO check must go to the default domain, not custom-team
            .Post(MakeLoginInfoResponse("PASSWORD+SK"))
            .ExpectUrl("my.1password.com")
            // 2. Regular login goes to the custom domain
            //    We don't want to test the rest of the login flow here, so we let it fail on an unknown response and call it a day
            .Get("""{"reason": "non-sso-reached"}""", HttpStatusCode.Forbidden)
            .ExpectUrl("custom-team.1password.com");

        // Act
        var act = () =>
            Client.LogIn(credentials, TestData.AppInfo, new CancelingUi(), new NullStorage(), (IRestTransport)flow, CancellationToken.None);

        // Assert
        var ex = await act.ShouldThrowAsync<InternalErrorException>();
        ex.Message.ShouldContain("non-sso-reached");
    }

    //
    // Helpers
    //

    private static string MakeLoginInfoResponse(params string[] authMethodTypes)
    {
        var methods = string.Join(", ", authMethodTypes.Select(t => $$"""{"type": "{{t}}"}"""));
        return $$"""{"userUuid": "user-uuid", "signInAddress": "https://my.1password.com", "authMethods": [{{methods}}]}""";
    }

    //
    // Data
    //

    private const string SsoApiUrl = "https://my.1password.com/api";
}
