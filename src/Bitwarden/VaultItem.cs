// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Bitwarden;

public record VaultItem
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Note { get; init; }
    public required string Folder { get; init; }
    public required string[] CollectionIds { get; init; }
    public required bool HidePassword { get; init; }
    public required CustomField[] CustomFields { get; init; }
}

public record CustomField(string Name, string Value);
