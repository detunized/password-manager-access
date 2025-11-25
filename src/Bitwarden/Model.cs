// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

// Everything in this class is public on purpose, even though it's only used internally.
// This is done to avoid problems with code obfuscation. The deserialization doesn't work when
// any names here get changed.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Bitwarden;

internal static class Model
{
    public class Error
    {
        [JsonPropertyName("error")]
        [JsonProperty(PropertyName = "error")]
        public string? Id { get; set; }

        [JsonPropertyName("error_description")]
        [JsonProperty(PropertyName = "error_description")]
        public string? Description { get; set; }

        [JsonPropertyName("Message")]
        [JsonProperty(PropertyName = "Message")]
        public string? Message { get; set; }

        [JsonPropertyName("ErrorModel")]
        [JsonProperty(PropertyName = "ErrorModel")]
        public ErrorModel? Info { get; set; }
    }

    public class ErrorModel
    {
        [JsonPropertyName("Message")]
        [JsonProperty(PropertyName = "Message")]
        public string? Message { get; set; }
    }

    public enum KdfMethod
    {
        Pbkdf2Sha256 = 0,
        Argon2id = 1,
    }

    public class KdfInfo
    {
        [JsonPropertyName("kdf")]
        [JsonProperty(PropertyName = "kdf", Required = Required.Always)]
        public KdfMethod Kdf { get; set; }

        [JsonPropertyName("kdfIterations")]
        [JsonProperty(PropertyName = "kdfIterations", Required = Required.Always)]
        public int Iterations { get; set; }

        [JsonPropertyName("kdfMemory")]
        [JsonProperty(PropertyName = "kdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory { get; set; }

        [JsonPropertyName("kdfParallelism")]
        [JsonProperty(PropertyName = "kdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism { get; set; }
    }

    public class AuthToken
    {
        [JsonPropertyName("token_type")]
        [JsonProperty(PropertyName = "token_type", Required = Required.Always)]
        public required string TokenType { get; set; }

        [JsonPropertyName("access_token")]
        [JsonProperty(PropertyName = "access_token", Required = Required.Always)]
        public required string AccessToken { get; set; }

        // Optional
        [JsonPropertyName("TwoFactorToken")]
        [JsonProperty(PropertyName = "TwoFactorToken")]
        public string? TwoFactorToken { get; set; }
    }

    public enum SecondFactorMethod
    {
        GoogleAuth = 0,
        Email = 1,
        Duo = 2,
        YubiKey = 3,
        U2f = 4,
        RememberMe = 5,
        DuoOrg = 6,
    }

    [JsonObject(ItemRequired = Required.Always)]
    public class SecondFactor
    {
        [JsonPropertyName("TwoFactorProviders2")]
        [JsonProperty(PropertyName = "TwoFactorProviders2")]
        public Dictionary<SecondFactorMethod, JObject>? Methods { get; set; }
    }

    [JsonObject(ItemRequired = Required.Always)]
    public class Vault
    {
        [JsonPropertyName("Profile")]
        [JsonProperty(PropertyName = "Profile")]
        public required Profile Profile { get; set; }

        [JsonPropertyName("Ciphers")]
        [JsonProperty(PropertyName = "Ciphers")]
        public required Item[] Ciphers { get; set; }

        [JsonPropertyName("Folders")]
        [JsonProperty(PropertyName = "Folders")]
        public required Folder[] Folders { get; set; }

        [JsonPropertyName("Collections")]
        [JsonProperty(PropertyName = "Collections")]
        public required Collection[] Collections { get; set; }
    }

    public class Profile
    {
        [JsonPropertyName("Email")]
        [JsonProperty(PropertyName = "Email")]
        public required string Email { get; set; }

        [JsonPropertyName("Key")]
        [JsonProperty(PropertyName = "Key")]
        public string? Key { get; set; }

        [JsonPropertyName("PrivateKey")]
        [JsonProperty(PropertyName = "PrivateKey")]
        public string? PrivateKey { get; set; }

        [JsonPropertyName("Organizations")]
        [JsonProperty(PropertyName = "Organizations")]
        public Organization[]? Organizations { get; set; }
    }

    public class Organization
    {
        [JsonPropertyName("id")]
        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        [JsonProperty(PropertyName = "name", Required = Required.Always)]
        public required string Name { get; set; }

        [JsonPropertyName("key")]
        [JsonProperty(PropertyName = "key", Required = Required.Always)]
        public required string Key { get; set; }
    }

    [JsonObject(ItemRequired = Required.Always)]
    public class Folder
    {
        [JsonPropertyName("Id")]
        [JsonProperty(PropertyName = "Id")]
        public required string Id { get; set; }

        [JsonPropertyName("Name")]
        [JsonProperty(PropertyName = "Name")]
        public required string Name { get; set; }
    }

    public class Collection
    {
        [JsonPropertyName("id")]
        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        [JsonProperty(PropertyName = "name", Required = Required.Always)]
        public required string Name { get; set; }

        [JsonPropertyName("organizationId")]
        [JsonProperty(PropertyName = "organizationId")]
        public string? OrganizationId { get; set; }

        [JsonPropertyName("hidePasswords")]
        [JsonProperty(PropertyName = "hidePasswords")]
        public bool HidePasswords { get; set; }
    }

    public enum ItemType
    {
        Login = 1,
        SecureNote = 2,
        Card = 3,
        Identity = 4,
        SshKey = 5,
    }

    public class Item
    {
        [JsonPropertyName("type")]
        [JsonProperty(PropertyName = "type", Required = Required.Always)]
        public ItemType Type { get; set; }

        [JsonPropertyName("id")]
        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        [JsonProperty(PropertyName = "name")]
        public string? Name { get; set; }

        [JsonPropertyName("notes")]
        [JsonProperty(PropertyName = "notes")]
        public string? Notes { get; set; }

        [JsonPropertyName("folderId")]
        [JsonProperty(PropertyName = "folderId")]
        public string? FolderId { get; set; }

        [JsonPropertyName("organizationId")]
        [JsonProperty(PropertyName = "organizationId")]
        public string? OrganizationId { get; set; }

        [JsonPropertyName("deletedDate")]
        [JsonProperty(PropertyName = "deletedDate")]
        public string? DeletedDate { get; set; }

        [JsonPropertyName("collectionIds")]
        [JsonProperty(PropertyName = "collectionIds")]
        public string[]? CollectionIds { get; set; }

        [JsonPropertyName("key")]
        [JsonProperty(PropertyName = "key")]
        public string? Key { get; set; }

        [JsonPropertyName("fields")]
        [JsonProperty(PropertyName = "fields")]
        public Field[]? Fields { get; set; }

        [JsonPropertyName("login")]
        [JsonProperty(PropertyName = "login", NullValueHandling = NullValueHandling.Ignore)]
        public LoginInfo? Login { get; set; }

        [JsonPropertyName("sshKey")]
        [JsonProperty(PropertyName = "sshKey", NullValueHandling = NullValueHandling.Ignore)]
        public SshKeyInfo? SshKey { get; set; }
    }

    public class Field
    {
        [JsonPropertyName("type")]
        [JsonProperty(PropertyName = "type", Required = Required.Always)]
        public required int Type { get; set; }

        [JsonPropertyName("name")]
        [JsonProperty(PropertyName = "name")]
        public string? Name { get; set; }

        [JsonPropertyName("value")]
        [JsonProperty(PropertyName = "value")]
        public string? Value { get; set; }

        [JsonPropertyName("linkedId")]
        [JsonProperty(PropertyName = "linkedId")]
        public int? LinkedId { get; set; }
    }

    public class LoginInfo
    {
        [JsonPropertyName("username")]
        [JsonProperty(PropertyName = "username")]
        public string? Username { get; set; }

        [JsonPropertyName("password")]
        [JsonProperty(PropertyName = "password")]
        public string? Password { get; set; }

        [JsonPropertyName("uri")]
        [JsonProperty(PropertyName = "uri")]
        public string? Uri { get; set; }

        [JsonPropertyName("totp")]
        [JsonProperty(PropertyName = "totp")]
        public string? Totp { get; set; }
    }

    public class SshKeyInfo
    {
        [JsonPropertyName("publicKey")]
        [JsonProperty(PropertyName = "publicKey")]
        public string? PublicKey { get; set; }

        [JsonPropertyName("privateKey")]
        [JsonProperty(PropertyName = "privateKey")]
        public string? PrivateKey { get; set; }

        [JsonPropertyName("keyFingerprint")]
        [JsonProperty(PropertyName = "keyFingerprint")]
        public string? Fingerprint { get; set; }
    }

    //
    // CLI/API
    //

    internal class TokenCliApi
    {
        [JsonPropertyName("token_type")]
        [JsonProperty(PropertyName = "token_type", Required = Required.Always)]
        public required string TokenType { get; set; }

        [JsonPropertyName("access_token")]
        [JsonProperty(PropertyName = "access_token", Required = Required.Always)]
        public required string AccessToken { get; set; }

        [JsonPropertyName("Kdf")]
        [JsonProperty(PropertyName = "Kdf", Required = Required.Always)]
        public required KdfMethod Kdf { get; set; }

        [JsonPropertyName("KdfIterations")]
        [JsonProperty(PropertyName = "KdfIterations", Required = Required.Always)]
        public required int KdfIterations { get; set; }

        [JsonPropertyName("KdfMemory")]
        [JsonProperty(PropertyName = "KdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory { get; set; }

        [JsonPropertyName("KdfParallelism")]
        [JsonProperty(PropertyName = "KdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism { get; set; }
    }

    public record FolderList([JsonProperty("data", Required = Required.Always)] Folder[] Folders);

    public record CollectionList([JsonProperty("data", Required = Required.Always)] Collection[] Collections);
}
