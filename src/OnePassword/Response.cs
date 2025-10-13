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
    internal record UserLoginInfo
    {
        [JsonProperty("userUuid")]
        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonProperty("signInAddress")]
        [JsonPropertyName("signInAddress")]
        public required string Url { get; init; }
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record NewSession
    {
        [JsonProperty("status", Required = Required.Always)]
        [JsonPropertyName("status")]
        public required string Status { get; init; }

        [JsonProperty("sessionID", Required = Required.Always)]
        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        [JsonProperty("accountKeyFormat")]
        [JsonPropertyName("accountKeyFormat")]
        public string KeyFormat { get; init; }

        [JsonProperty("accountKeyUuid")]
        [JsonPropertyName("accountKeyUuid")]
        public string KeyUuid { get; init; }

        [JsonProperty("userAuth")]
        [JsonPropertyName("userAuth")]
        public UserAuth Auth { get; init; }
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record UserAuth
    {
        [JsonProperty("method")]
        [JsonPropertyName("method")]
        public string Method { get; init; }

        [JsonProperty("alg")]
        [JsonPropertyName("alg")]
        public string Algorithm { get; init; }

        [JsonProperty("iterations")]
        [JsonPropertyName("iterations")]
        public int Iterations { get; init; }

        [JsonProperty("salt")]
        [JsonPropertyName("salt")]
        public string Salt { get; init; }
    }

    internal record struct SuccessStatus
    {
        [JsonProperty("success", Required = Required.Always)]
        [JsonPropertyName("success")]
        public required int Success { get; init; }
    }

    // For the time being this class has both Newtonsoft.Json and System.Text.Json attributes
    internal record Encrypted
    {
        [JsonProperty("kid", Required = Required.Always)]
        [JsonPropertyName("kid")]
        public required string KeyId { get; init; }

        [JsonProperty("enc", Required = Required.Always)]
        [JsonPropertyName("enc")]
        public required string Scheme { get; init; }

        [JsonProperty("cty", Required = Required.Always)]
        [JsonPropertyName("cty")]
        public required string Container { get; init; }

        [JsonProperty("iv")]
        [JsonPropertyName("iv")]
        public string Iv { get; init; }

        [JsonProperty("data", Required = Required.Always)]
        [JsonPropertyName("data")]
        public required string Ciphertext { get; init; }
    }

    internal record AccountInfo
    {
        [JsonProperty("me", Required = Required.Always)]
        [JsonPropertyName("me")]
        public required MeInfo Me { get; init; }

        [JsonProperty("vaults", Required = Required.Always)]
        [JsonPropertyName("vaults")]
        public required VaultInfo[] Vaults { get; init; }
    }

    internal record MeInfo
    {
        [JsonProperty("vaultAccess", Required = Required.Always)]
        [JsonPropertyName("vaultAccess")]
        public required VaultAccessInfo[] VaultAccess { get; init; }
    }

    internal record VaultAccessInfo
    {
        [JsonProperty("vaultUuid", Required = Required.Always)]
        [JsonPropertyName("vaultUuid")]
        public required string Id { get; init; }

        [JsonProperty("acl", Required = Required.Always)]
        [JsonPropertyName("acl")]
        public required int Acl { get; init; }

        [JsonProperty("encVaultKey", Required = Required.Always)]
        [JsonPropertyName("encVaultKey")]
        public required Encrypted EncryptedKey { get; init; }
    }

    internal record VaultInfo
    {
        [JsonProperty("uuid", Required = Required.Always)]
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonProperty("encAttrs", Required = Required.Always)]
        [JsonPropertyName("encAttrs")]
        public required Encrypted Attributes { get; init; }

        [JsonProperty("access", Required = Required.Always)]
        [JsonPropertyName("access")]
        public required VaultAccessInfo[] Access { get; init; }
    }

    internal record VaultAttributes
    {
        [JsonProperty("name", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("name")]
        public string Name { get; init; }

        [JsonProperty("desc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("desc")]
        public string Description { get; init; }
    }

    internal record KeysetsInfo
    {
        [JsonProperty("keysets", Required = Required.Always)]
        [JsonPropertyName("keysets")]
        public required KeysetInfo[] Keysets { get; init; }
    }

    internal record KeysetInfo
    {
        [JsonProperty("uuid", Required = Required.Always)]
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonProperty("encryptedBy", Required = Required.Always)]
        [JsonPropertyName("encryptedBy")]
        public required string EncryptedBy { get; init; }

        [JsonProperty("sn", Required = Required.Always)]
        [JsonPropertyName("sn")]
        public required int SerialNumber { get; init; }

        [JsonProperty("encSymKey", Required = Required.Always)]
        [JsonPropertyName("encSymKey")]
        public required KeyDerivationInfo KeyOrMasterKey { get; init; }

        [JsonProperty("encPriKey", Required = Required.Always)]
        [JsonPropertyName("encPriKey")]
        public required Encrypted PrivateKey { get; init; }
    }

    internal record AesKey
    {
        [JsonProperty("kid", Required = Required.Always)]
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonProperty("k", Required = Required.Always)]
        [JsonPropertyName("k")]
        public required string Key { get; init; }
    }

    internal record RsaKey
    {
        [JsonProperty("kid", Required = Required.Always)]
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonProperty("e", Required = Required.Always)]
        [JsonPropertyName("e")]
        public required string Exponent { get; init; }

        [JsonProperty("n", Required = Required.Always)]
        [JsonPropertyName("n")]
        public required string Modulus { get; init; }

        [JsonProperty("p", Required = Required.Always)]
        [JsonPropertyName("p")]
        public required string P { get; init; }

        [JsonProperty("q", Required = Required.Always)]
        [JsonPropertyName("q")]
        public required string Q { get; init; }

        [JsonProperty("dp", Required = Required.Always)]
        [JsonPropertyName("dp")]
        public required string DP { get; init; }

        [JsonProperty("dq", Required = Required.Always)]
        [JsonPropertyName("dq")]
        public required string DQ { get; init; }

        [JsonProperty("qi", Required = Required.Always)]
        [JsonPropertyName("qi")]
        public required string InverseQ { get; init; }

        [JsonProperty("d", Required = Required.Always)]
        [JsonPropertyName("d")]
        public required string D { get; init; }
    }

    // All these fields here are optional because for the master key and the master key only we have
    // more fields. For the master key these fields are not optional, but there's no way to express
    // this with attributes.
    internal record KeyDerivationInfo : Encrypted
    {
        [JsonProperty("alg")]
        [JsonPropertyName("alg")]
        public string Algorithm { get; init; }

        [JsonProperty("p2s")]
        [JsonPropertyName("p2s")]
        public string Salt { get; init; }

        [JsonProperty("p2c")]
        [JsonPropertyName("p2c")]
        public int Iterations { get; init; }
    }

    internal record VerifyKey
    {
        [JsonProperty("accountUuid", Required = Required.Always)]
        [JsonPropertyName("accountUuid")]
        public required string AccountId { get; init; }

        [JsonProperty("userUuid", Required = Required.Always)]
        [JsonPropertyName("userUuid")]
        public required string UserId { get; init; }

        [JsonProperty("serverVerifyHash", Required = Required.Always)]
        [JsonPropertyName("serverVerifyHash")]
        public required string ServerHash { get; init; }

        [JsonProperty("mfa")]
        [JsonPropertyName("mfa")]
        public MfaInfo Mfa { get; init; }
    }

    internal record MfaInfo
    {
        [JsonProperty("dsecret")]
        [JsonPropertyName("dsecret")]
        public BasicMfa RememberMe { get; init; }

        [JsonProperty("totp")]
        [JsonPropertyName("totp")]
        public BasicMfa GoogleAuth { get; init; }

        [JsonProperty("webAuthn")]
        [JsonPropertyName("webAuthn")]
        public WebAuthnMfa WebAuthn { get; init; }

        [JsonProperty("duo")]
        [JsonPropertyName("duo")]
        public DuoMfa Duo { get; init; }
    }

    internal record BasicMfa
    {
        [JsonProperty("enabled", Required = Required.Always)]
        [JsonPropertyName("enabled")]
        public required bool Enabled { get; init; }
    }

    internal record WebAuthnMfa : BasicMfa
    {
        [JsonProperty("keyHandles")]
        [JsonPropertyName("keyHandles")]
        public string[] KeyHandles { get; init; }

        [JsonProperty("challenge")]
        [JsonPropertyName("challenge")]
        public string Challenge { get; init; }
    }

    internal record DuoMfa : BasicMfa
    {
        // Cannot make these fields required in case they are not sent when Duo is disabled.
        // Need to check for validity later where they are being used.
        [JsonProperty("host")]
        [JsonPropertyName("host")]
        public string Host { get; init; }

        [JsonProperty("sigRequest")]
        [JsonPropertyName("sigRequest")]
        public string Signature { get; init; }

        [JsonProperty("authURL")]
        [JsonPropertyName("authURL")]
        public string Url { get; init; }
    }

    internal record Error
    {
        [JsonProperty("errorCode", Required = Required.Always)]
        [JsonPropertyName("errorCode")]
        public required int Code { get; init; }

        [JsonProperty("errorMessage", Required = Required.Always)]
        [JsonPropertyName("errorMessage")]
        public required string Message { get; init; }
    }

    internal record FailureReason
    {
        [JsonProperty("reason", Required = Required.Always)]
        [JsonPropertyName("reason")]
        public required string Reason { get; init; }
    }

    internal record Mfa
    {
        [JsonProperty("dsecret", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("dsecret")]
        public string RememberMeToken { get; init; }
    }

    internal record VaultItemsBatch
    {
        [JsonProperty("contentVersion", Required = Required.Always)]
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonProperty("items")]
        [JsonPropertyName("items")]
        public VaultItem[] Items { get; init; }

        [JsonProperty("batchComplete", Required = Required.Always)]
        [JsonPropertyName("batchComplete")]
        public required bool Complete { get; init; }
    }

    internal record SingleVaultItem
    {
        [JsonProperty("contentVersion", Required = Required.Always)]
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonProperty("item", Required = Required.Always)]
        [JsonPropertyName("item")]
        public required VaultItem Item { get; init; }
    }

    internal record VaultItem
    {
        [JsonProperty("uuid", Required = Required.Always)]
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonProperty("templateUuid", Required = Required.Always)]
        [JsonPropertyName("templateUuid")]
        public required string TemplateId { get; init; }

        [JsonProperty("trashed", Required = Required.Always)]
        [JsonPropertyName("trashed")]
        public required string Deleted { get; init; }

        [JsonProperty("itemVersion", Required = Required.Always)]
        [JsonPropertyName("itemVersion")]
        public required int Version { get; init; }

        [JsonProperty("encryptedBy", Required = Required.Always)]
        [JsonPropertyName("encryptedBy")]
        public required string EncryptedBy { get; init; }

        [JsonProperty("encOverview", Required = Required.Always)]
        [JsonPropertyName("encOverview")]
        public required Encrypted Overview { get; init; }

        [JsonProperty("encDetails", Required = Required.Always)]
        [JsonPropertyName("encDetails")]
        public required Encrypted Details { get; init; }
    }

    internal record VaultItemOverview
    {
        [JsonProperty("title")]
        [JsonPropertyName("title")]
        public string Title { get; init; }

        [JsonProperty("ainfo")]
        [JsonPropertyName("ainfo")]
        public string AdditionalInfo { get; init; }

        [JsonProperty("url")]
        [JsonPropertyName("url")]
        public string Url { get; init; }

        [JsonProperty("URLs")]
        [JsonPropertyName("URLs")]
        public VaultItemUrl[] Urls { get; init; }
    }

    internal record VaultItemUrl
    {
        [JsonProperty("l", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("l")]
        public string Name { get; init; }

        [JsonProperty("u", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("u")]
        public string Url { get; init; }
    }

    internal record VaultItemDetails
    {
        [JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("title")]
        public string Name { get; init; }

        [JsonProperty("url", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("url")]
        public string Url { get; init; }

        [JsonProperty("notesPlain", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("notesPlain")]
        public string Note { get; init; }

        [JsonProperty("fields")]
        [JsonPropertyName("fields")]
        public VaultItemField[] Fields { get; init; }

        [JsonProperty("sections")]
        [JsonPropertyName("sections")]
        public VaultItemSection[] Sections { get; init; }
    }

    internal record VaultItemField
    {
        [JsonProperty("designation", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("designation")]
        public string Designation { get; init; }

        [JsonProperty("value", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("value")]
        public string Value { get; init; }
    }

    internal record VaultItemSection
    {
        [JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        [JsonPropertyName("title")]
        public string Name { get; init; }

        [JsonProperty("fields")]
        [JsonPropertyName("fields")]
        public VaultItemSectionField[] Fields { get; init; }
    }

    internal record VaultItemSectionField
    {
        [JsonProperty("n")]
        [JsonPropertyName("n")]
        public string Id { get; init; }

        [JsonProperty("t")]
        [JsonPropertyName("t")]
        public string Name { get; init; }

        [Newtonsoft.Json.JsonConverter(typeof(VaultItemSectionFieldValueConverter))]
        [JsonProperty("v")]
        [JsonPropertyName("v")]
        public string Value { get; init; }

        [JsonProperty("k")]
        [JsonPropertyName("k")]
        public string Kind { get; init; }

        [JsonProperty("a")]
        [JsonPropertyName("a")]
        public VaultItemFieldAttributes Attributes { get; init; }
    }

    internal record VaultItemFieldAttributes
    {
        [JsonProperty("guarded")]
        [JsonPropertyName("guarded")]
        public string Guarded { get; init; }

        [JsonProperty("sshKeyAttributes")]
        [JsonPropertyName("sshKeyAttributes")]
        public SshKeyAttributes SshKey { get; init; }
    }

    internal record SshKeyAttributes
    {
        [JsonProperty("privateKey")]
        [JsonPropertyName("privateKey")]
        public string PrivateKey { get; init; }

        [JsonProperty("publicKey")]
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; init; }

        [JsonProperty("fingerprint")]
        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; init; }

        [JsonProperty("keyType")]
        [JsonPropertyName("keyType")]
        public SshKeyType KeyType { get; init; }
    }

    internal record SshKeyType
    {
        [JsonProperty("t")]
        [JsonPropertyName("t")]
        public string Type { get; init; }

        [JsonProperty("c")]
        [JsonPropertyName("c")]
        public int Bits { get; init; }
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

    internal record AForBV1
    {
        [JsonProperty("sessionID", Required = Required.Always)]
        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        [JsonProperty("userB", Required = Required.Always)]
        [JsonPropertyName("userB")]
        public required string B { get; init; }
    }

    //
    // SrpV2
    //

    internal record AForBV2
    {
        [JsonPropertyName("userB")]
        public required string B { get; init; }
    }

    internal record ServerHash
    {
        [JsonPropertyName("serverVerifyHash")]
        public required string ServerVerifyHash { get; init; }
    }

    internal record ServiceAccountToken
    {
        [JsonProperty("signInAddress")]
        [JsonPropertyName("signInAddress")]
        public string Domain { get; init; }

        [JsonProperty("email")]
        [JsonPropertyName("email")]
        public string Username { get; init; }

        [JsonProperty("secretKey")]
        [JsonPropertyName("secretKey")]
        public string AccountKey { get; init; }

        [JsonProperty("deviceUuid")]
        [JsonPropertyName("deviceUuid")]
        public string DeviceUuid { get; init; }

        [JsonProperty("srpX")]
        [JsonPropertyName("srpX")]
        public string SrpX { get; init; }

        [JsonProperty("muk")]
        [JsonPropertyName("muk")]
        public AesKey MasterUnlockKey { get; init; }
    }
}
