// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;

// Everything in this namespace is public on purpose, even though it's only used internally.
// This is done to avoid problems with code obfuscation. The deserialization doesn't work when
// any names here get changed.
namespace Bitwarden.Response
{
    [JsonObject(ItemRequired = Required.Always)]
    public struct KdfInfo
    {
        public int Kdf;
        public int KdfIterations;
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct AuthToken
    {
        [JsonProperty(PropertyName = "token_type")]
        public string TokenType;

        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken;
    }

    public enum SecondFactorMethod
    {
        GAuth = 0,
        Email = 1,
        Duo = 2,
        YubiKey = 3,
    }

    [JsonObject(ItemRequired = Required.Always)]
    public struct SecondFactor
    {
        [JsonProperty(PropertyName = "TwoFactorProviders2")]
        public Dictionary<SecondFactorMethod, object> Methods;
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
