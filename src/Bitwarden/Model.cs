// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

// Everything in this class is public on purpose, even though it's only used internally.
// This is done to avoid problems with code obfuscation. The deserialization doesn't work when
// any names here get changed.

using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Bitwarden;

internal static class Model
{
    public class Error
    {
        [JsonProperty(PropertyName = "error")]
        public string? Id { get; set; }

        [JsonProperty(PropertyName = "error_description")]
        public string? Description { get; set; }

        [JsonProperty(PropertyName = "Message")]
        public string? Message { get; set; }

        [JsonProperty(PropertyName = "ErrorModel")]
        public ErrorModel? Info { get; set; }
    }

    public class ErrorModel
    {
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
        [JsonProperty(PropertyName = "kdf", Required = Required.Always)]
        public KdfMethod Kdf { get; set; }

        [JsonProperty(PropertyName = "kdfIterations", Required = Required.Always)]
        public int Iterations { get; set; }

        [JsonProperty(PropertyName = "kdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory { get; set; }

        [JsonProperty(PropertyName = "kdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism { get; set; }
    }

    public class AuthToken
    {
        [JsonProperty(PropertyName = "token_type", Required = Required.Always)]
        public required string TokenType { get; set; }

        [JsonProperty(PropertyName = "access_token", Required = Required.Always)]
        public required string AccessToken { get; set; }

        // Optional
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
        [JsonProperty(PropertyName = "TwoFactorProviders2")]
        public Dictionary<SecondFactorMethod, JObject>? Methods { get; set; }
    }

    [JsonObject(ItemRequired = Required.Always)]
    public class Vault
    {
        [JsonProperty(PropertyName = "Profile")]
        public required Profile Profile { get; set; }

        [JsonProperty(PropertyName = "Ciphers")]
        public required Item[] Ciphers { get; set; }

        [JsonProperty(PropertyName = "Folders")]
        public required Folder[] Folders { get; set; }

        [JsonProperty(PropertyName = "Collections")]
        public required Collection[] Collections { get; set; }
    }

    public class Profile
    {
        [JsonProperty(PropertyName = "Email")]
        public required string Email { get; set; }

        [JsonProperty(PropertyName = "Key")]
        public string? Key { get; set; }

        [JsonProperty(PropertyName = "PrivateKey")]
        public string? PrivateKey { get; set; }

        [JsonProperty(PropertyName = "Organizations")]
        public Organization[]? Organizations { get; set; }
    }

    public class Organization
    {
        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonProperty(PropertyName = "name", Required = Required.Always)]
        public required string Name { get; set; }

        [JsonProperty(PropertyName = "key", Required = Required.Always)]
        public required string Key { get; set; }
    }

    [JsonObject(ItemRequired = Required.Always)]
    public class Folder
    {
        [JsonProperty(PropertyName = "Id")]
        public required string Id { get; set; }

        [JsonProperty(PropertyName = "Name")]
        public required string Name { get; set; }
    }

    public class Collection
    {
        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonProperty(PropertyName = "name", Required = Required.Always)]
        public required string Name { get; set; }

        [JsonProperty(PropertyName = "organizationId")]
        public string? OrganizationId { get; set; }

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
        [JsonProperty(PropertyName = "type", Required = Required.Always)]
        public ItemType Type { get; set; }

        [JsonProperty(PropertyName = "id", Required = Required.Always)]
        public required string Id { get; set; }

        [JsonProperty(PropertyName = "name")]
        public string? Name { get; set; }

        [JsonProperty(PropertyName = "notes")]
        public string? Notes { get; set; }

        [JsonProperty(PropertyName = "folderId")]
        public string? FolderId { get; set; }

        [JsonProperty(PropertyName = "organizationId")]
        public string? OrganizationId { get; set; }

        [JsonProperty(PropertyName = "deletedDate")]
        public string? DeletedDate { get; set; }

        [JsonProperty(PropertyName = "collectionIds")]
        public string[]? CollectionIds { get; set; }

        [JsonProperty(PropertyName = "key")]
        public string? Key { get; set; }

        [JsonProperty(PropertyName = "fields")]
        public Field[]? Fields { get; set; }

        [JsonProperty(PropertyName = "login", NullValueHandling = NullValueHandling.Ignore)]
        public LoginInfo? Login { get; set; }

        [JsonProperty(PropertyName = "sshKey", NullValueHandling = NullValueHandling.Ignore)]
        public SshKeyInfo? SshKey { get; set; }
    }

    public class Field
    {
        [JsonProperty(PropertyName = "type", Required = Required.Always)]
        public required int Type { get; set; }

        [JsonProperty(PropertyName = "name")]
        public string? Name { get; set; }

        [JsonProperty(PropertyName = "value")]
        public string? Value { get; set; }

        [JsonProperty(PropertyName = "linkedId")]
        public int? LinkedId { get; set; }
    }

    public class LoginInfo
    {
        [JsonProperty(PropertyName = "username")]
        public string? Username { get; set; }

        [JsonProperty(PropertyName = "password")]
        public string? Password { get; set; }

        [JsonProperty(PropertyName = "uri")]
        public string? Uri { get; set; }

        [JsonProperty(PropertyName = "totp")]
        public string? Totp { get; set; }
    }

    public class SshKeyInfo
    {
        [JsonProperty(PropertyName = "publicKey")]
        public string? PublicKey { get; set; }

        [JsonProperty(PropertyName = "privateKey")]
        public string? PrivateKey { get; set; }

        [JsonProperty(PropertyName = "keyFingerprint")]
        public string? Fingerprint { get; set; }
    }

    //
    // CLI/API
    //

    internal class TokenCliApi
    {
        [JsonProperty(PropertyName = "token_type", Required = Required.Always)]
        public required string TokenType { get; set; }

        [JsonProperty(PropertyName = "access_token", Required = Required.Always)]
        public required string AccessToken { get; set; }

        [JsonProperty(PropertyName = "Kdf", Required = Required.Always)]
        public required KdfMethod Kdf { get; set; }

        [JsonProperty(PropertyName = "KdfIterations", Required = Required.Always)]
        public required int KdfIterations { get; set; }

        [JsonProperty(PropertyName = "KdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory { get; set; }

        [JsonProperty(PropertyName = "KdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism { get; set; }
    }

    public record FolderList([JsonProperty("data", Required = Required.Always)] Folder[] Folders);

    public record CollectionList([JsonProperty("data", Required = Required.Always)] Collection[] Collections);
}
