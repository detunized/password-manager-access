// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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
