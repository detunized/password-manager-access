// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.ComponentModel;
using Newtonsoft.Json;

// TODO: Rename to Wire or Model since not all this things are responses
namespace PasswordManagerAccess.OnePassword.Response
{
    internal class NewSession
    {
        [JsonProperty(PropertyName = "status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty(PropertyName = "sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty(PropertyName = "accountKeyFormat")]
        public readonly string KeyFormat;

        [JsonProperty(PropertyName = "accountKeyUuid")]
        public readonly string KeyUuid;

        [JsonProperty(PropertyName = "userAuth")]
        public readonly UserAuth Auth;
    }

    internal class UserAuth
    {
        [JsonProperty(PropertyName = "method")]
        public readonly string Method;

        [JsonProperty(PropertyName = "alg")]
        public readonly string Algorithm;

        [JsonProperty(PropertyName = "iterations")]
        public readonly int Iterations;

        [JsonProperty(PropertyName = "salt")]
        public readonly string Salt;
    }

    internal struct SuccessStatus
    {
        [JsonProperty(PropertyName = "success", Required = Required.Always)]
        public readonly int Success;
    }

    internal class Encrypted
    {
        [JsonProperty(PropertyName = "kid", Required = Required.Always)]
        public readonly string KeyId;

        [JsonProperty(PropertyName = "enc", Required = Required.Always)]
        public readonly string Scheme;

        [JsonProperty(PropertyName = "cty", Required = Required.Always)]
        public readonly string Container;

        [JsonProperty(PropertyName = "iv")]
        public readonly string Iv;

        [JsonProperty(PropertyName = "data", Required = Required.Always)]
        public readonly string Ciphertext;
    }

    internal class AccountInfo
    {
        [JsonProperty(PropertyName = "me", Required = Required.Always)]
        public readonly MeInfo Me;

        [JsonProperty(PropertyName = "vaults", Required = Required.Always)]
        public readonly VaultInfo[] Vaults;
    }

    internal class MeInfo
    {
        [JsonProperty(PropertyName = "vaultAccess", Required = Required.Always)]
        public readonly VaultAccessInfo[] VaultAceess;
    }

    internal class VaultAccessInfo
    {
        [JsonProperty(PropertyName = "vaultUuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty(PropertyName = "acl", Required = Required.Always)]
        public readonly int Acl;

        [JsonProperty(PropertyName = "encVaultKey", Required = Required.Always)]
        public readonly Encrypted EncryptedKey;
    }

    internal class VaultInfo
    {
        [JsonProperty(PropertyName = "uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty(PropertyName = "encAttrs", Required = Required.Always)]
        public readonly Encrypted Attributes;
    }

    internal class VaultAttributes
    {
        [JsonProperty(PropertyName = "name", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty(PropertyName = "desc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Description;
    }

    internal class KeysetsInfo
    {
        [JsonProperty(PropertyName = "keysets", Required = Required.Always)]
        public readonly KeysetInfo[] Keysets;
    }

    internal class KeysetInfo
    {
        [JsonProperty(PropertyName = "encryptedBy", Required = Required.Always)]
        public readonly string EncryptedBy;

        [JsonProperty(PropertyName = "sn", Required = Required.Always)]
        public readonly int SerialNumber;

        [JsonProperty(PropertyName = "encSymKey", Required = Required.Always)]
        public readonly KeyDerivationInfo KeyOrMasterKey;

        [JsonProperty(PropertyName = "encPriKey", Required = Required.Always)]
        public readonly Encrypted PrivateKey;
    }

    internal class AesKey
    {
        [JsonProperty("kid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("k", Required = Required.Always)]
        public readonly string Key;
    }

    internal class RsaKey
    {
        [JsonProperty("kid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("e", Required = Required.Always)]
        public readonly string Exponent;

        [JsonProperty("n", Required = Required.Always)]
        public readonly string Modulus;

        [JsonProperty("p", Required = Required.Always)]
        public readonly string P;

        [JsonProperty("q", Required = Required.Always)]
        public readonly string Q;

        [JsonProperty("dp", Required = Required.Always)]
        public readonly string DP;

        [JsonProperty("dq", Required = Required.Always)]
        public readonly string DQ;

        [JsonProperty("qi", Required = Required.Always)]
        public readonly string InverseQ;

        [JsonProperty("d", Required = Required.Always)]
        public readonly string D;
    }

    // All these fields here are optional because for the master key and the master key only we have
    // more fields. For the master key these fields are not optional, but there's no way to express
    // this with attributes.
    internal class KeyDerivationInfo : Encrypted
    {
        [JsonProperty(PropertyName = "alg")]
        public readonly string Algorithm;

        [JsonProperty(PropertyName = "p2s")]
        public readonly string Salt;

        [JsonProperty(PropertyName = "p2c")]
        public readonly int Iterations;
    }

    internal class VerifyKey
    {
        [JsonProperty(PropertyName = "accountUuid", Required = Required.Always)]
        public readonly string AccountId;

        [JsonProperty(PropertyName = "userUuid", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty(PropertyName = "serverVerifyHash", Required = Required.Always)]
        public readonly string ServerHash;

        [JsonProperty(PropertyName = "mfa")]
        public readonly MfaInfo Mfa;
    }

    internal class MfaInfo
    {
        [JsonProperty(PropertyName = "dsecret")]
        public readonly MfaEnabled RememberMe;

        [JsonProperty(PropertyName = "totp")]
        public readonly MfaEnabled GoogleAuth;
    }

    internal class MfaEnabled
    {
        [JsonProperty(PropertyName = "enabled", Required = Required.Always)]
        public readonly bool Enabled;
    }

    internal class Error
    {
        [JsonProperty(PropertyName = "errorCode", Required = Required.Always)]
        public readonly int Code;

        [JsonProperty(PropertyName = "errorMessage")]
        public readonly string Message;
    }

    internal class Mfa
    {
        [JsonProperty(PropertyName = "dsecret", Required = Required.Always)]
        public readonly string RememberMeToken;
    }

    internal class VaultItemsBatch
    {
        [JsonProperty(PropertyName = "contentVersion", Required = Required.Always)]
        public readonly int Version;

        [JsonProperty(PropertyName = "items")]
        public readonly VaultItem[] Items;

        [JsonProperty(PropertyName = "batchComplete", Required = Required.Always)]
        public readonly bool Complete;
    }

    internal class VaultItem
    {
        [JsonProperty("uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("templateUuid", Required = Required.Always)]
        public readonly string TemplateId;

        [JsonProperty("trashed", Required = Required.Always)]
        public readonly string Deleted;

        [JsonProperty("itemVersion", Required = Required.Always)]
        public readonly int Version;

        [JsonProperty("encryptedBy", Required = Required.Always)]
        public readonly string EncryptedBy;

        [JsonProperty("encOverview", Required = Required.Always)]
        public readonly Encrypted Overview;

        [JsonProperty("encDetails", Required = Required.Always)]
        public readonly Encrypted Details;
    }

    internal class VaultItemOverview
    {
        [JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Title;

        [JsonProperty("url", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Url;

        [JsonProperty("URLs")]
        public readonly VaultItemUrl[] Urls;
    }

    internal class VaultItemUrl
    {
        [JsonProperty("l", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty("u", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Url;
    }

    internal class VaultItemDetails
    {
        [JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty("url", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Url;

        [JsonProperty("notesPlain", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Note;

        [JsonProperty("fields")]
        public readonly VaultItemField[] Fields;

        [JsonProperty("sections")]
        public readonly VaultItemSection[] Sections;
    }

    internal class VaultItemField
    {
        [JsonProperty("designation", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Designation;

        [JsonProperty("value", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Value;
    }

    internal class VaultItemSection
    {
        [JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty("fields")]
        public readonly VaultItemSectionField[] Fields;
    }

    internal class VaultItemSectionField
    {
        [JsonProperty("t", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty("v", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Value;
    }

    internal class AForB
    {
        [JsonProperty(PropertyName = "sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty(PropertyName = "userB", Required = Required.Always)]
        public readonly string B;
    }
}
