// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.ComponentModel;
using System.Text.Json.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using JsonRequiredAttribute = System.Text.Json.Serialization.JsonRequiredAttribute;

// TODO: Merge with Model
namespace PasswordManagerAccess.OnePassword.Response
{
    internal class UserLoginInfo
    {
        [JsonProperty("userUuid")]
        public readonly string UserUuid;

        [JsonProperty("signInAddress")]
        public readonly string Url;
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal class NewSession
    {
        [JsonProperty("status", Required = Required.Always)]
        [JsonPropertyName("status"), JsonRequired]
        public string Status { get; set; }

        [JsonProperty("sessionID", Required = Required.Always)]
        [JsonPropertyName("sessionID"), JsonRequired]
        public string SessionId { get; set; }

        [JsonProperty("accountKeyFormat")]
        [JsonPropertyName("accountKeyFormat"), JsonRequired]
        public string KeyFormat { get; set; }

        [JsonProperty("accountKeyUuid")]
        [JsonPropertyName("accountKeyUuid"), JsonRequired]
        public string KeyUuid { get; set; }

        [JsonProperty("userAuth")]
        [JsonPropertyName("userAuth"), JsonRequired]
        public UserAuth Auth { get; set; }
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal class UserAuth
    {
        [JsonProperty("method")]
        [JsonPropertyName("method"), JsonRequired]
        public string Method { get; set; }

        [JsonProperty("alg")]
        [JsonPropertyName("alg"), JsonRequired]
        public string Algorithm { get; set; }

        [JsonProperty("iterations")]
        [JsonPropertyName("iterations"), JsonRequired]
        public int Iterations { get; set; }

        [JsonProperty("salt")]
        [JsonPropertyName("salt"), JsonRequired]
        public string Salt { get; set; }
    }

    internal struct SuccessStatus
    {
        [JsonProperty("success", Required = Required.Always)]
        public readonly int Success;
    }

    // For the time being this class has both Newtonsoft.Json and System.Text.Json attributes
    internal class Encrypted
    {
        [JsonProperty("kid", Required = Required.Always)]
        [JsonPropertyName("kid"), JsonRequired]
        public string KeyId { get; set; }

        [JsonProperty("enc", Required = Required.Always)]
        [JsonPropertyName("enc"), JsonRequired]
        public string Scheme { get; set; }

        [JsonProperty("cty", Required = Required.Always)]
        [JsonPropertyName("cty"), JsonRequired]
        public string Container { get; set; }

        [JsonProperty("iv")]
        [JsonPropertyName("iv")]
        public string Iv { get; set; }

        [JsonProperty("data", Required = Required.Always)]
        [JsonPropertyName("data"), JsonRequired]
        public string Ciphertext { get; set; }
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
        public readonly VaultAccessInfo[] VaultAccess;
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

        [JsonProperty("access", Required = Required.Always)]
        public readonly VaultAccessInfo[] Access;
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
        [JsonProperty("uuid", Required = Required.Always)]
        public readonly string Id;

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
        public readonly BasicMfa RememberMe;

        [JsonProperty("totp")]
        public readonly BasicMfa GoogleAuth;

        [JsonProperty("webAuthn")]
        public readonly WebAuthnMfa WebAuthn;

        [JsonProperty("duo")]
        public readonly DuoMfa Duo;
    }

    internal class BasicMfa
    {
        [JsonProperty("enabled", Required = Required.Always)]
        public readonly bool Enabled;
    }

    internal class WebAuthnMfa : BasicMfa
    {
        [JsonProperty("keyHandles")]
        public readonly string[] KeyHandles;

        [JsonProperty("challenge")]
        public readonly string Challenge;
    }

    internal class DuoMfa : BasicMfa
    {
        // Cannot make these fields required in case they are not sent when Duo is disabled.
        // Need to check for validity later where they are being used.

        [JsonProperty("host")]
        public readonly string Host;

        [JsonProperty("sigRequest")]
        public readonly string Signature;

        [JsonProperty("authURL")]
        public readonly string Url;
    }

    internal class Error
    {
        [JsonProperty("errorCode", Required = Required.Always)]
        public readonly int Code;

        [JsonProperty("errorMessage", Required = Required.Always)]
        public readonly string Message;
    }

    internal class FailureReason
    {
        [JsonProperty("reason", Required = Required.Always)]
        public readonly string Reason;
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

    internal record SingleVaultItem(
        [JsonProperty("contentVersion", Required = Required.Always)] int Version,
        [JsonProperty("item", Required = Required.Always)] VaultItem Item
    );

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
        [JsonProperty("title")]
        public readonly string Title;

        [JsonProperty("ainfo")]
        public readonly string AdditionalInfo;

        [JsonProperty("url")]
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
        [JsonProperty("n")]
        public readonly string Id;

        [JsonProperty("t")]
        public readonly string Name;

        [Newtonsoft.Json.JsonConverter(typeof(VaultItemSectionFieldValueConverter))]
        [JsonProperty("v")]
        public readonly string Value;

        [JsonProperty("k")]
        public readonly string Kind;

        [JsonProperty("a")]
        public readonly VaultItemFieldAttributes Attributes;
    }

    internal class VaultItemFieldAttributes
    {
        [JsonProperty("guarded")]
        public readonly string Guarded;

        [JsonProperty("sshKeyAttributes")]
        public readonly SshKeyAttributes SshKey;
    }

    internal class SshKeyAttributes
    {
        [JsonProperty("privateKey")]
        public readonly string PrivateKey;

        [JsonProperty("publicKey")]
        public readonly string PublicKey;

        [JsonProperty("fingerprint")]
        public readonly string Fingerprint;

        [JsonProperty("keyType")]
        public readonly SshKeyType KeyType;
    }

    internal class SshKeyType
    {
        [JsonProperty("t")]
        public readonly string Type;

        [JsonProperty("c")]
        public readonly int Bits;
    }

    // The "v" value could be practically anything. We are only interested in the string values.
    // The rest is simply converted to JSON as a fallback.
    internal class VaultItemSectionFieldValueConverter : Newtonsoft.Json.JsonConverter<string>
    {
        public override string ReadJson(JsonReader reader, Type objectType, string existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            var token = JToken.Load(reader);
            return token.Type switch
            {
                JTokenType.String => token.Value<string>(),
                _ => token.ToString(Formatting.None),
            };
        }

        public override void WriteJson(JsonWriter writer, string value, JsonSerializer serializer) => throw new NotImplementedException();
    }

    //
    // SrpV1
    //

    internal class AForBV1
    {
        [JsonProperty("sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty("userB", Required = Required.Always)]
        public readonly string B;
    }

    //
    // SrpV2
    //

    internal record AForBV2([property: JsonPropertyName("userB"), JsonRequired] string B);

    internal record ServerHash([property: JsonPropertyName("serverVerifyHash"), JsonRequired] string ServerVerifyHash);

    internal class ServiceAccountToken
    {
        [JsonProperty("signInAddress")]
        public readonly string Domain;

        [JsonProperty("email")]
        public readonly string Username;

        [JsonProperty("secretKey")]
        public readonly string AccountKey;

        [JsonProperty("deviceUuid")]
        public readonly string DeviceUuid;

        [JsonProperty("srpX")]
        public readonly string SrpX;

        [JsonProperty("muk")]
        public readonly AesKey MasterUnlockKey;
    }
}
