// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// Everything in this namespace is public on purpose, even though it's only used internally.
// This is done to avoid problems with code obfuscation. The deserialization doesn't work when
// any names here get changed.
namespace PasswordManagerAccess.Bitwarden.Response
{
    public struct Error
    {
        [JsonProperty(PropertyName = "error")]
        public string Id;

        [JsonProperty(PropertyName = "error_description")]
        public string Description;

        [JsonProperty(PropertyName = "Message")]
        public string Message;

        [JsonProperty(PropertyName = "ErrorModel")]
        public ErrorModel Info;
    }

    public struct ErrorModel
    {
        public string Message;
    }

    public enum KdfMethod
    {
        Pbkdf2Sha256 = 0,
        Argon2id = 1,
    }

    public struct KdfInfo
    {
        [JsonProperty("kdf", Required = Required.Always)]
        public KdfMethod Kdf;

        [JsonProperty("kdfIterations", Required = Required.Always)]
        public int Iterations;

        [JsonProperty("kdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory;

        [JsonProperty("kdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism;
    }

    public struct AuthToken
    {
        [JsonProperty(PropertyName = "token_type", Required = Required.Always)]
        public string TokenType;

        [JsonProperty(PropertyName = "access_token", Required = Required.Always)]
        public string AccessToken;

        // Optional
        public string TwoFactorToken;
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
    public struct SecondFactor
    {
        [JsonProperty(PropertyName = "TwoFactorProviders2")]
        public Dictionary<SecondFactorMethod, JObject> Methods;
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct Vault
    {
        public Profile Profile;
        public Item[] Ciphers;
        public Folder[] Folders;
        public Collection[] Collections;
    }

    public struct Profile
    {
        public string Email;
        public string Key;
        public string PrivateKey;
        public Organization[] Organizations;
    }

    public struct Organization
    {
        [JsonProperty("id", Required = Required.Always)]
        public string Id;

        [JsonProperty("name", Required = Required.Always)]
        public string Name;

        [JsonProperty("key", Required = Required.Always)]
        public string Key;
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct Folder
    {
        public string Id;
        public string Name;
    }

    public struct Collection
    {
        [JsonProperty("id", Required = Required.Always)]
        public string Id;

        [JsonProperty("name", Required = Required.Always)]
        public string Name;

        [JsonProperty("organizationId")]
        public string OrganizationId;

        [JsonProperty("hidePasswords")]
        public bool HidePasswords;
    }

    public enum ItemType
    {
        Login = 1,
        SecureNote = 2,
        Card = 3,
        Identity = 4,
    }

    public struct Item
    {
        [JsonProperty("type", Required = Required.Always)]
        public ItemType Type;

        [JsonProperty("id", Required = Required.Always)]
        public string Id;

        [JsonProperty("name")]
        public string Name;

        [JsonProperty("notes")]
        public string Notes;

        [JsonProperty("folderId")]
        public string FolderId;

        [JsonProperty("organizationId")]
        public string OrganizationId;

        [JsonProperty("deletedDate")]
        public string DeletedDate;

        [JsonProperty("collectionIds")]
        public string[] CollectionIds;

        [JsonProperty("key")]
        public string Key;

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public LoginInfo Login;
    }

    public struct LoginInfo
    {
        [JsonProperty("username")]
        public string Username;

        [JsonProperty("password")]
        public string Password;

        [JsonProperty("uri")]
        public string Uri;

        [JsonProperty("totp")]
        public string Totp;
    }

    //
    // CLI/API
    //

    internal class TokenCliApi
    {
        [JsonProperty("token_type", Required = Required.Always)]
        public string TokenType;

        [JsonProperty("access_token", Required = Required.Always)]
        public string AccessToken;

        [JsonProperty("Kdf", Required = Required.Always)]
        public KdfMethod Kdf;

        [JsonProperty("KdfIterations", Required = Required.Always)]
        public int KdfIterations;

        [JsonProperty("KdfMemory", NullValueHandling = NullValueHandling.Ignore)]
        public int Memory;

        [JsonProperty("KdfParallelism", NullValueHandling = NullValueHandling.Ignore)]
        public int Parallelism;
    }
}
