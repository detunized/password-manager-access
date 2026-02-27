// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Text.Json.Serialization;

namespace PasswordManagerAccess.NordPass;

internal static class Model
{
    // POST /v1/users/oauth/login
    public record OAuthLoginResponse
    {
        [JsonPropertyName("attempt_id")]
        public required string AttemptId { get; init; }

        [JsonPropertyName("redirect_url")]
        public required string RedirectUrl { get; init; }
    }

    // POST /v1/users/oauth/token
    public record OAuthTokenResponse
    {
        [JsonPropertyName("token")]
        public required OAuthToken Token { get; init; }
    }

    public record OAuthToken
    {
        [JsonPropertyName("token")]
        public required string Token { get; init; }

        [JsonPropertyName("expires_at")]
        public required string ExpiresAt { get; init; }

        [JsonPropertyName("renew_token")]
        public required string RefreshToken { get; init; }

        [JsonPropertyName("renew_expires_at")]
        public required string RefreshExpiresAt { get; init; }
    }

    // Vault fixture (for testing)
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

    // Encrypted vault item, could be: "folder", "item" or "option"
    // Option we ignore.
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

        [JsonPropertyName("folder_id")]
        public string? FolderId { get; init; }
    }

    // API error response for checking error codes
    public record ApiErrorResponse
    {
        [JsonPropertyName("errors")]
        public ApiError? Errors { get; init; }
    }

    public record ApiError
    {
        [JsonPropertyName("code")]
        public int Code { get; init; }
    }

    // Stored auth for token persistence
    internal record StoredAuth
    {
        [JsonPropertyName("accessToken")]
        public required string AccessToken { get; init; }

        [JsonPropertyName("expiresAt")]
        public required DateTime ExpiresAt { get; init; }

        [JsonPropertyName("refreshToken")]
        public required string RefreshToken { get; init; }

        [JsonPropertyName("refreshExpiresAt")]
        public required DateTime RefreshExpiresAt { get; init; }
    }

    // Outer wrapper for decrypted item value: {"type":"password","value":"{...}"}
    public record DecryptedItemWrapper
    {
        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("value")]
        public required string Value { get; init; }
    }

    // Inner JSON from the value field for "folder" items
    public record DecryptedFolder
    {
        [JsonPropertyName("title")]
        public string? Title { get; init; }
    }

    // Inner JSON from the value field for "password" items
    public record DecryptedPassword
    {
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

        [JsonPropertyName("additional_urls")]
        public string?[]? AdditionalUrls { get; init; }

        [JsonPropertyName("custom_fields")]
        public DecryptedCustomField[]? CustomFields { get; init; }
    }

    public record DecryptedCustomField
    {
        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("label")]
        public string? Label { get; init; }

        [JsonPropertyName("value")]
        public string? Value { get; init; }
    }
}
