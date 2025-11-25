// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Bitwarden;

public record SshKey : VaultItem
{
    public required string PublicKey { get; init; }
    public required string PrivateKey { get; init; }
    public required string Fingerprint { get; init; }
}
