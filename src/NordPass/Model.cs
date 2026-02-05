// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Text.Json.Serialization;

namespace PasswordManagerAccess.NordPass;

internal static class Model
{
    public record Vault
    {
        [JsonPropertyName("identities")]
        public required Identity[] Identities { get; init; }

        [JsonPropertyName("vaultItems")]
        public required VaultItem[] VaultItems { get; init; }
    }

    public record Identity
    {
        [JsonPropertyName("identity_id")]
        public required string IdentityId { get; init; }

        [JsonPropertyName("user_id")]
        public int UserId { get; init; }

        [JsonPropertyName("keys")]
        public required IdentityKey[] Keys { get; init; }
    }

    public record IdentityKey
    {
        [JsonPropertyName("identity_key_id")]
        public required string IdentityKeyId { get; init; }

        [JsonPropertyName("public_key")]
        public required string PublicKey { get; init; }

        [JsonPropertyName("encrypted_private_key")]
        public required string EncryptedPrivateKey { get; init; }

        [JsonPropertyName("salt")]
        public required string Salt { get; init; }

        [JsonPropertyName("dek_info")]
        public required string DekInfo { get; init; }
    }

    // GET /v2/users/identities/items
    public record VaultItemsResponse
    {
        [JsonPropertyName("items")]
        public required VaultItem[] Items { get; init; }
    }

    public record VaultItem
    {
        [JsonPropertyName("item_id")]
        public required string ItemId { get; init; }

        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("value")]
        public required string Value { get; init; }

        [JsonPropertyName("encrypted_value_key")]
        public required string EncryptedValueKey { get; init; }

        [JsonPropertyName("public_key")]
        public required string PublicKey { get; init; }

        [JsonPropertyName("dek_info")]
        public required string DekInfo { get; init; }

        [JsonPropertyName("item_key")]
        public required ItemKey ItemKey { get; init; }
    }

    public record ItemKey
    {
        [JsonPropertyName("encrypted_item_private_key")]
        public required string EncryptedItemPrivateKey { get; init; }

        [JsonPropertyName("public_key")]
        public required string PublicKey { get; init; }

        [JsonPropertyName("dek_info")]
        public required string DekInfo { get; init; }
    }

    // Decrypted vault item value (inner JSON)
    public record DecryptedValue
    {
        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("uuid")]
        public string? Uuid { get; init; }

        [JsonPropertyName("title")]
        public string? Title { get; init; }

        [JsonPropertyName("username")]
        public string? Username { get; init; }

        [JsonPropertyName("secret")]
        public string? Secret { get; init; }

        [JsonPropertyName("url")]
        public string? Url { get; init; }

        [JsonPropertyName("note")]
        public string? Note { get; init; }
    }
}
