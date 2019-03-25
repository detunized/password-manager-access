// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// Everything in this namespace is public on purpose, even though it's only used internally.
// This is done to avoid problems with code obfuscation. The deserialization doesn't work when
// any names here get changed.
namespace PasswordManagerAccess.Bitwarden.Response
{
    public enum KdfMethod
    {
        Pbkdf2Sha256 = 0,
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct KdfInfo
    {
        public KdfMethod Kdf;
        public int KdfIterations;
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

        RememberMe = 5,
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
    }

    public struct Profile
    {
        public string Key;
        public string PrivateKey;
        public Organization[] Organizations;
    }

    public struct Organization
    {
        public string Id;
        public string Name;
        public string Key;
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct Folder
    {
        public string Id;
        public string Name;
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
        [JsonProperty(Required = Required.Always)]
        public ItemType Type;

        public string Id;
        public string Name;
        public string Notes;
        public string FolderId;
        public string OrganizationId;

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public LoginInfo Login;
    }

    public struct LoginInfo
    {
        public string Username;
        public string Password;
        public string Uri;
    }
}
