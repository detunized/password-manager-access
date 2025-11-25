// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Bitwarden;

public record Account : VaultItem
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required string Url { get; init; }
    public required string Totp { get; init; }
}
