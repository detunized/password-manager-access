// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Text.Json.Serialization;

namespace PasswordManagerAccess.Bitwarden;

internal static class Model
{
    public record Error
    {
        [JsonPropertyName("error")]
        public string? Id { get; init; }

        [JsonPropertyName("error_description")]
        public string? Description { get; init; }

        [JsonPropertyName("Message")]
        public string? Message { get; init; }

        [JsonPropertyName("ErrorModel")]
        public ErrorModel? Info { get; init; }
    }

    public record ErrorModel
    {
        [JsonPropertyName("Message")]
        public string? Message { get; init; }
    }

    public enum KdfMethod
    {
        Pbkdf2Sha256 = 0,
        Argon2id = 1,
    }

    public record KdfInfo
    {
        [JsonPropertyName("kdf")]
        public required KdfMethod Kdf { get; init; }

        [JsonPropertyName("kdfIterations")]
        public int Iterations { get; init; }

        // Optional, as it's only available for Argon2id
        [JsonPropertyName("kdfMemory")]
        public int? Memory { get; init; }

        // Optional, as it's only available for Argon2id
        [JsonPropertyName("kdfParallelism")]
        public int? Parallelism { get; init; }
    }

    public record Vault
    {
        [JsonPropertyName("profile")]
        public required Profile Profile { get; init; }

        [JsonPropertyName("ciphers")]
        public required Item[] Ciphers { get; init; }

        [JsonPropertyName("folders")]
        public required Folder[] Folders { get; init; }

        [JsonPropertyName("collections")]
        public required Collection[] Collections { get; init; }
    }

    public record Profile
    {
        [JsonPropertyName("email")]
        public required string Email { get; init; }

        // Optional, as originally it was not present and some legacy vaults might not have it
        [JsonPropertyName("key")]
        public string? Key { get; init; }

        // Optional, as originally it was only present for users with sharing enabled
        [JsonPropertyName("privateKey")]
        public string? PrivateKey { get; init; }

        // Optional, as it's only present for users org users. Most of the time it's an empty array though.
        [JsonPropertyName("organizations")]
        public Organization[]? Organizations { get; init; }
    }

    public record Organization
    {
        [JsonPropertyName("id")]
        public required string Id { get; init; }

        [JsonPropertyName("name")]
        public required string Name { get; init; }

        [JsonPropertyName("key")]
        public required string Key { get; init; }
    }

    public record Folder
    {
        [JsonPropertyName("id")]
        public required string Id { get; init; }

        [JsonPropertyName("name")]
        public required string Name { get; init; }
    }

    public record Collection
    {
        [JsonPropertyName("id")]
        public required string Id { get; init; }

        [JsonPropertyName("name")]
        public required string Name { get; init; }

        [JsonPropertyName("organizationId")]
        public string? OrganizationId { get; init; }

        [JsonPropertyName("hidePasswords")]
        public bool HidePasswords { get; init; }
    }

    public enum ItemType
    {
        Login = 1,
        SecureNote = 2,
        Card = 3,
        Identity = 4,
        SshKey = 5,
    }

    public record Item
    {
        [JsonPropertyName("type")]
        public ItemType Type { get; init; }

        [JsonPropertyName("id")]
        public required string Id { get; init; }

        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("notes")]
        public string? Notes { get; init; }

        [JsonPropertyName("folderId")]
        public string? FolderId { get; init; }

        [JsonPropertyName("organizationId")]
        public string? OrganizationId { get; init; }

        [JsonPropertyName("deletedDate")]
        public string? DeletedDate { get; init; }

        [JsonPropertyName("collectionIds")]
        public string[]? CollectionIds { get; init; }

        [JsonPropertyName("key")]
        public string? Key { get; init; }

        [JsonPropertyName("fields")]
        public Field[]? Fields { get; init; }

        [JsonPropertyName("login")]
        public LoginInfo? Login { get; init; }

        [JsonPropertyName("sshKey")]
        public SshKeyInfo? SshKey { get; init; }
    }

    public record Field
    {
        [JsonPropertyName("type")]
        public required int Type { get; init; }

        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("value")]
        public string? Value { get; init; }

        [JsonPropertyName("linkedId")]
        public int? LinkedId { get; init; }
    }

    public record LoginInfo
    {
        [JsonPropertyName("username")]
        public string? Username { get; init; }

        [JsonPropertyName("password")]
        public string? Password { get; init; }

        [JsonPropertyName("uri")]
        public string? Uri { get; init; }

        [JsonPropertyName("totp")]
        public string? Totp { get; init; }
    }

    public record SshKeyInfo
    {
        [JsonPropertyName("publicKey")]
        public string? PublicKey { get; init; }

        [JsonPropertyName("privateKey")]
        public string? PrivateKey { get; init; }

        [JsonPropertyName("keyFingerprint")]
        public string? Fingerprint { get; init; }
    }

    //
    // CLI/API
    //

    // Note: All Kdf* properties are capitalized in the CLI/API responses. This is on purpose. They are not capitalized in the browser mode.
    internal record TokenCliApi
    {
        [JsonPropertyName("token_type")]
        public required string TokenType { get; init; }

        [JsonPropertyName("access_token")]
        public required string AccessToken { get; init; }

        [JsonPropertyName("Kdf")]
        public required KdfMethod Kdf { get; init; }

        [JsonPropertyName("KdfIterations")]
        public required int KdfIterations { get; init; }

        // Optional, as it's only available for Argon2id
        [JsonPropertyName("KdfMemory")]
        public int? Memory { get; init; }

        // Optional, as it's only available for Argon2id
        [JsonPropertyName("KdfParallelism")]
        public int? Parallelism { get; init; }
    }

    public record FolderList
    {
        [JsonPropertyName("data")]
        public required Folder[] Folders { get; init; }
    }

    public record CollectionList
    {
        [JsonPropertyName("data")]
        public required Collection[] Collections { get; init; }
    }
}
