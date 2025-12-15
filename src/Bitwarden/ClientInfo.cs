// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Bitwarden;

public record ClientInfoApi
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string Password { get; init; }
    public required string DeviceId { get; init; }

    // Base URL for the Bitwarden API. Defaults to the US region.
    public string BaseUrl { get; init; } = Client.DefaultBaseUlr;
}

public record ClientInfoSso
{
    public required string Password { get; init; }
    public required string DeviceId { get; init; }

    // Organization is optional and could be left blank. When it's not provided the
    // SSO login page is going to ask the user to enter the organization identifier.
    public string Organization { get; init; } = "";

    // Base URL for the Bitwarden SSO. Defaults to the US region.
    public string BaseUrl { get; init; } = Client.DefaultBaseUlr;
}
