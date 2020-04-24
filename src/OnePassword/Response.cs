// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.ComponentModel;
using Newtonsoft.Json;

// TODO: Rename to Wire or Model since not all this things are responses
namespace PasswordManagerAccess.OnePassword.Response
{
    internal class NewSession
    {
        [JsonProperty("status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty("sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty("accountKeyFormat")]
        public readonly string KeyFormat;

        [JsonProperty("accountKeyUuid")]
        public readonly string KeyUuid;

        [JsonProperty("userAuth")]
        public readonly UserAuth Auth;
    }

    internal class UserAuth
    {
        [JsonProperty("method")]
        public readonly string Method;

        [JsonProperty("alg")]
        public readonly string Algorithm;

        [JsonProperty("iterations")]
        public readonly int Iterations;

        [JsonProperty("salt")]
        public readonly string Salt;
    }

    internal struct SuccessStatus
    {
        [JsonProperty("success", Required = Required.Always)]
        public readonly int Success;
    }

    internal class Encrypted
    {
        [JsonProperty("kid", Required = Required.Always)]
        public readonly string KeyId;

        [JsonProperty("enc", Required = Required.Always)]
        public readonly string Scheme;

        [JsonProperty("cty", Required = Required.Always)]
        public readonly string Container;

        [JsonProperty("iv")]
        public readonly string Iv;

        [JsonProperty("data", Required = Required.Always)]
        public readonly string Ciphertext;
    }

    internal class AccountInfo
    {
        [JsonProperty("me", Required = Required.Always)]
        public readonly MeInfo Me;

        [JsonProperty("vaults", Required = Required.Always)]
        public readonly VaultInfo[] Vaults;
    }

    internal class MeInfo
    {
        [JsonProperty("vaultAccess", Required = Required.Always)]
        public readonly VaultAccessInfo[] VaultAceess;
    }

    internal class VaultAccessInfo
    {
        [JsonProperty("vaultUuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("acl", Required = Required.Always)]
        public readonly int Acl;

        [JsonProperty("encVaultKey", Required = Required.Always)]
        public readonly Encrypted EncryptedKey;
    }

    internal class VaultInfo
    {
        [JsonProperty("uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("encAttrs", Required = Required.Always)]
        public readonly Encrypted Attributes;
    }

    internal class VaultAttributes
    {
        [JsonProperty("name", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Name;

        [JsonProperty("desc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string Description;
    }

    internal class KeysetsInfo
    {
        [JsonProperty("keysets", Required = Required.Always)]
        public readonly KeysetInfo[] Keysets;
    }

    internal class KeysetInfo
    {
        [JsonProperty("encryptedBy", Required = Required.Always)]
        public readonly string EncryptedBy;

        [JsonProperty("sn", Required = Required.Always)]
        public readonly int SerialNumber;

        [JsonProperty("encSymKey", Required = Required.Always)]
        public readonly KeyDerivationInfo KeyOrMasterKey;

        [JsonProperty("encPriKey", Required = Required.Always)]
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
        [JsonProperty("alg")]
        public readonly string Algorithm;

        [JsonProperty("p2s")]
        public readonly string Salt;

        [JsonProperty("p2c")]
        public readonly int Iterations;
    }

    internal class VerifyKey
    {
        [JsonProperty("accountUuid", Required = Required.Always)]
        public readonly string AccountId;

        [JsonProperty("userUuid", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty("serverVerifyHash", Required = Required.Always)]
        public readonly string ServerHash;

        [JsonProperty("mfa")]
        public readonly MfaInfo Mfa;
    }

    internal class MfaInfo
    {
        [JsonProperty("dsecret")]
        public readonly MfaEnabled RememberMe;

        [JsonProperty("totp")]
        public readonly MfaEnabled GoogleAuth;
    }

    internal class MfaEnabled
    {
        [JsonProperty("enabled", Required = Required.Always)]
        public readonly bool Enabled;
    }

    internal class Error
    {
        [JsonProperty("errorCode", Required = Required.Always)]
        public readonly int Code;

        [JsonProperty("errorMessage", Required = Required.Always)]
        public readonly string Message;
    }

    internal class Mfa
    {
        [JsonProperty("dsecret", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string RememberMeToken;
    }

    internal class VaultItemsBatch
    {
        [JsonProperty("contentVersion", Required = Required.Always)]
        public readonly int Version;

        [JsonProperty("items")]
        public readonly VaultItem[] Items;

        [JsonProperty("batchComplete", Required = Required.Always)]
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
        [JsonProperty("sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty("userB", Required = Required.Always)]
        public readonly string B;
    }
}
