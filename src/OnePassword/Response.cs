// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Serialization;

// ReSharper disable CheckNamespace
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

// TODO: Merge with Model
namespace PasswordManagerAccess.OnePassword.Response
{
    internal record UserLoginInfo
    {
        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonPropertyName("signInAddress")]
        public required string Url { get; init; }
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record NewSession
    {
        [JsonPropertyName("status")]
        public required string Status { get; init; }

        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        [JsonPropertyName("accountKeyFormat")]
        public string KeyFormat { get; init; }

        [JsonPropertyName("accountKeyUuid")]
        public string KeyUuid { get; init; }

        [JsonPropertyName("userAuth")]
        public UserAuth Auth { get; init; }
    }

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record UserAuth
    {
        [JsonPropertyName("method")]
        public string Method { get; init; }

        [JsonPropertyName("alg")]
        public string Algorithm { get; init; }

        [JsonPropertyName("iterations")]
        public int Iterations { get; init; }

        [JsonPropertyName("salt")]
        public string Salt { get; init; }
    }

    internal record struct SuccessStatus
    {
        [JsonPropertyName("success")]
        public required int Success { get; init; }
    }

    // For the time being this class has both Newtonsoft.Json and System.Text.Json attributes
    internal record Encrypted
    {
        [JsonPropertyName("kid")]
        public required string KeyId { get; init; }

        [JsonPropertyName("enc")]
        public required string Scheme { get; init; }

        [JsonPropertyName("cty")]
        public required string Container { get; init; }

        [JsonPropertyName("iv")]
        public string Iv { get; init; }

        [JsonPropertyName("data")]
        public required string Ciphertext { get; init; }
    }

    internal record AccountInfo
    {
        [JsonPropertyName("me")]
        public required MeInfo Me { get; init; }

        [JsonPropertyName("vaults")]
        public required VaultInfo[] Vaults { get; init; }
    }

    internal record MeInfo
    {
        [JsonPropertyName("vaultAccess")]
        public required VaultAccessInfo[] VaultAccess { get; init; }
    }

    internal record VaultAccessInfo
    {
        [JsonPropertyName("vaultUuid")]
        public required string Id { get; init; }

        [JsonPropertyName("acl")]
        public required int Acl { get; init; }

        [JsonPropertyName("encVaultKey")]
        public required Encrypted EncryptedKey { get; init; }
    }

    internal record VaultInfo
    {
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonPropertyName("encAttrs")]
        public required Encrypted Attributes { get; init; }

        [JsonPropertyName("access")]
        public required VaultAccessInfo[] Access { get; init; }
    }

    internal record VaultAttributes
    {
        [DefaultValue("")]
        [JsonPropertyName("name")]
        public string Name { get; init; }

        [DefaultValue("")]
        [JsonPropertyName("desc")]
        public string Description { get; init; }
    }

    internal record KeysetsInfo
    {
        [JsonPropertyName("keysets")]
        public required KeysetInfo[] Keysets { get; init; }
    }

    internal record KeysetInfo
    {
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonPropertyName("encryptedBy")]
        public required string EncryptedBy { get; init; }

        [JsonPropertyName("sn")]
        public required int SerialNumber { get; init; }

        [JsonPropertyName("encSymKey")]
        public required KeyDerivationInfo KeyOrMasterKey { get; init; }

        [JsonPropertyName("encPriKey")]
        public required Encrypted PrivateKey { get; init; }
    }

    internal record AesKey
    {
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonPropertyName("k")]
        public required string Key { get; init; }
    }

    internal record RsaKey
    {
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonPropertyName("e")]
        public required string Exponent { get; init; }

        [JsonPropertyName("n")]
        public required string Modulus { get; init; }

        [JsonPropertyName("p")]
        public required string P { get; init; }

        [JsonPropertyName("q")]
        public required string Q { get; init; }

        [JsonPropertyName("dp")]
        public required string Dp { get; init; }

        [JsonPropertyName("dq")]
        public required string Dq { get; init; }

        [JsonPropertyName("qi")]
        public required string InverseQ { get; init; }

        [JsonPropertyName("d")]
        public required string D { get; init; }
    }

    // All these fields here are optional because for the master key and the master key only we have
    // more fields. For the master key these fields are not optional, but there's no way to express
    // this with attributes.
    internal record KeyDerivationInfo : Encrypted
    {
        [JsonPropertyName("alg")]
        public string Algorithm { get; init; }

        [JsonPropertyName("p2s")]
        public string Salt { get; init; }

        [JsonPropertyName("p2c")]
        public int Iterations { get; init; }
    }

    internal record VerifyKey
    {
        [JsonPropertyName("accountUuid")]
        public required string AccountId { get; init; }

        [JsonPropertyName("userUuid")]
        public required string UserId { get; init; }

        [JsonPropertyName("serverVerifyHash")]
        public required string ServerHash { get; init; }

        [JsonPropertyName("mfa")]
        public MfaInfo Mfa { get; init; }
    }

    internal record MfaInfo
    {
        [JsonPropertyName("dsecret")]
        public BasicMfa RememberMe { get; init; }

        [JsonPropertyName("totp")]
        public BasicMfa GoogleAuth { get; init; }

        [JsonPropertyName("webAuthn")]
        public WebAuthnMfa WebAuthn { get; init; }

        [JsonPropertyName("duo")]
        public DuoMfa Duo { get; init; }
    }

    internal record BasicMfa
    {
        [JsonPropertyName("enabled")]
        public required bool Enabled { get; init; }
    }

    internal record WebAuthnMfa : BasicMfa
    {
        [JsonPropertyName("keyHandles")]
        public string[] KeyHandles { get; init; }

        [JsonPropertyName("challenge")]
        public string Challenge { get; init; }
    }

    internal record DuoMfa : BasicMfa
    {
        // Cannot make these fields required in case they are not sent when Duo is disabled.
        // Need to check for validity later where they are being used.
        [JsonPropertyName("host")]
        public string Host { get; init; }

        [JsonPropertyName("sigRequest")]
        public string Signature { get; init; }

        [JsonPropertyName("authURL")]
        public string Url { get; init; }
    }

    internal record Error
    {
        [JsonPropertyName("errorCode")]
        public required int Code { get; init; }

        [JsonPropertyName("errorMessage")]
        public required string Message { get; init; }
    }

    internal record FailureReason
    {
        [JsonPropertyName("reason")]
        public required string Reason { get; init; }
    }

    internal record Mfa
    {
        [DefaultValue("")]
        [JsonPropertyName("dsecret")]
        public string RememberMeToken { get; init; }
    }

    internal record VaultItemsBatch
    {
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("items")]
        public VaultItem[] Items { get; init; }

        [JsonPropertyName("batchComplete")]
        public required bool Complete { get; init; }
    }

    internal record SingleVaultItem
    {
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("item")]
        public required VaultItem Item { get; init; }
    }

    internal record VaultItem
    {
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonPropertyName("templateUuid")]
        public required string TemplateId { get; init; }

        [JsonPropertyName("trashed")]
        public required string Deleted { get; init; }

        [JsonPropertyName("itemVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("encryptedBy")]
        public required string EncryptedBy { get; init; }

        [JsonPropertyName("encOverview")]
        public required Encrypted Overview { get; init; }

        [JsonPropertyName("encDetails")]
        public required Encrypted Details { get; init; }
    }

    internal record VaultItemOverview
    {
        [JsonPropertyName("title")]
        public string Title { get; init; }

        [JsonPropertyName("ainfo")]
        public string AdditionalInfo { get; init; }

        [JsonPropertyName("url")]
        public string Url { get; init; }

        [JsonPropertyName("URLs")]
        public VaultItemUrl[] Urls { get; init; }
    }

    internal record VaultItemUrl
    {
        [DefaultValue("")]
        [JsonPropertyName("l")]
        public string Name { get; init; }

        [DefaultValue("")]
        [JsonPropertyName("u")]
        public string Url { get; init; }
    }

    internal record VaultItemDetails
    {
        [DefaultValue("")]
        [JsonPropertyName("title")]
        public string Name { get; init; }

        [DefaultValue("")]
        [JsonPropertyName("url")]
        public string Url { get; init; }

        [DefaultValue("")]
        [JsonPropertyName("notesPlain")]
        public string Note { get; init; }

        [JsonPropertyName("fields")]
        public VaultItemField[] Fields { get; init; }

        [JsonPropertyName("sections")]
        public VaultItemSection[] Sections { get; init; }
    }

    internal record VaultItemField
    {
        [DefaultValue("")]
        [JsonPropertyName("designation")]
        public string Designation { get; init; }

        [DefaultValue("")]
        [JsonPropertyName("value")]
        public string Value { get; init; }
    }

    internal record VaultItemSection
    {
        [DefaultValue("")]
        [JsonPropertyName("title")]
        public string Name { get; init; }

        [JsonPropertyName("fields")]
        public VaultItemSectionField[] Fields { get; init; }
    }

    internal record VaultItemSectionField
    {
        [JsonPropertyName("n")]
        public string Id { get; init; }

        [JsonPropertyName("t")]
        public string Name { get; init; }

        [JsonConverter(typeof(VaultItemSectionFieldValueConverter))]
        [JsonPropertyName("v")]
        public string Value { get; init; }

        [JsonPropertyName("k")]
        public string Kind { get; init; }

        [JsonPropertyName("a")]
        public VaultItemFieldAttributes Attributes { get; init; }
    }

    internal record VaultItemFieldAttributes
    {
        [JsonPropertyName("guarded")]
        public string Guarded { get; init; }

        [JsonPropertyName("sshKeyAttributes")]
        public SshKeyAttributes SshKey { get; init; }
    }

    internal record SshKeyAttributes
    {
        [JsonPropertyName("privateKey")]
        public string PrivateKey { get; init; }

        [JsonPropertyName("publicKey")]
        public string PublicKey { get; init; }

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; init; }

        [JsonPropertyName("keyType")]
        public SshKeyType KeyType { get; init; }
    }

    internal record SshKeyType
    {
        [JsonPropertyName("t")]
        public string Type { get; init; }

        [JsonPropertyName("c")]
        public int Bits { get; init; }
    }

    // The "v" value could be practically anything. We are only interested in the string values.
    // The rest is simply converted to JSON as a fallback.
    internal class VaultItemSectionFieldValueConverter : JsonConverter<string>
    {
        public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            //throw new InvalidOperationException("Use ReadAsObject instead");

            // Read the entire value as a JsonElement first
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var element = jsonDoc.RootElement;

            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                _ => element.GetRawText(),
            };
        }

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }
    }

    //
    // SrpV1
    //

    internal record AForBv1
    {
        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        [JsonPropertyName("userB")]
        public required string B { get; init; }
    }

    //
    // SrpV2
    //

    internal record AForBv2
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
        [JsonPropertyName("signInAddress")]
        public string Domain { get; init; }

        [JsonPropertyName("email")]
        public string Username { get; init; }

        [JsonPropertyName("secretKey")]
        public string AccountKey { get; init; }

        [JsonPropertyName("deviceUuid")]
        public string DeviceUuid { get; init; }

        [JsonPropertyName("srpX")]
        public string SrpX { get; init; }

        [JsonPropertyName("muk")]
        public AesKey MasterUnlockKey { get; init; }
    }
}
