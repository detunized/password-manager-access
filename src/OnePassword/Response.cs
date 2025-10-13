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
    internal record UserLoginInfo(
        [property: JsonProperty("userUuid")] [property: JsonPropertyName("userUuid")] string UserUuid,
        [property: JsonProperty("signInAddress")] [property: JsonPropertyName("signInAddress")] string Url
    );

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record NewSession(
        [property: JsonProperty("status", Required = Required.Always)] [property: JsonPropertyName("status"), JsonRequired] string Status,
        [property: JsonProperty("sessionID", Required = Required.Always)] [property: JsonPropertyName("sessionID"), JsonRequired] string SessionId,
        [property: JsonProperty("accountKeyFormat")] [property: JsonPropertyName("accountKeyFormat")] string KeyFormat,
        [property: JsonProperty("accountKeyUuid")] [property: JsonPropertyName("accountKeyUuid")] string KeyUuid,
        [property: JsonProperty("userAuth")] [property: JsonPropertyName("userAuth")] UserAuth Auth
    );

    // This class has both Newtonsoft.Json and System.Text.Json attributes
    internal record UserAuth(
        [property: JsonProperty("method")] [property: JsonPropertyName("method")] string Method,
        [property: JsonProperty("alg")] [property: JsonPropertyName("alg")] string Algorithm,
        [property: JsonProperty("iterations")] [property: JsonPropertyName("iterations")] int Iterations,
        [property: JsonProperty("salt")] [property: JsonPropertyName("salt")] string Salt
    );

    internal record struct SuccessStatus(
        [property: JsonProperty("success", Required = Required.Always)] [property: JsonPropertyName("success"), JsonRequired] int Success
    );

    // For the time being this class has both Newtonsoft.Json and System.Text.Json attributes
    internal record Encrypted(
        [property: JsonProperty("kid", Required = Required.Always)] [property: JsonPropertyName("kid"), JsonRequired] string KeyId,
        [property: JsonProperty("enc", Required = Required.Always)] [property: JsonPropertyName("enc"), JsonRequired] string Scheme,
        [property: JsonProperty("cty", Required = Required.Always)] [property: JsonPropertyName("cty"), JsonRequired] string Container,
        [property: JsonProperty("iv")] [property: JsonPropertyName("iv")] string Iv,
        [property: JsonProperty("data", Required = Required.Always)] [property: JsonPropertyName("data"), JsonRequired] string Ciphertext
    );

    internal record AccountInfo(
        [property: JsonProperty("me", Required = Required.Always)] [property: JsonPropertyName("me"), JsonRequired] MeInfo Me,
        [property: JsonProperty("vaults", Required = Required.Always)] [property: JsonPropertyName("vaults"), JsonRequired] VaultInfo[] Vaults
    );

    internal record MeInfo(
        [property: JsonProperty("vaultAccess", Required = Required.Always)]
        [property: JsonPropertyName("vaultAccess"), JsonRequired]
            VaultAccessInfo[] VaultAccess
    );

    internal record VaultAccessInfo(
        [property: JsonProperty("vaultUuid", Required = Required.Always)] [property: JsonPropertyName("vaultUuid"), JsonRequired] string Id,
        [property: JsonProperty("acl", Required = Required.Always)] [property: JsonPropertyName("acl"), JsonRequired] int Acl,
        [property: JsonProperty("encVaultKey", Required = Required.Always)]
        [property: JsonPropertyName("encVaultKey"), JsonRequired]
            Encrypted EncryptedKey
    );

    internal record VaultInfo(
        [property: JsonProperty("uuid", Required = Required.Always)] [property: JsonPropertyName("uuid"), JsonRequired] string Id,
        [property: JsonProperty("encAttrs", Required = Required.Always)] [property: JsonPropertyName("encAttrs"), JsonRequired] Encrypted Attributes,
        [property: JsonProperty("access", Required = Required.Always)] [property: JsonPropertyName("access"), JsonRequired] VaultAccessInfo[] Access
    );

    internal record VaultAttributes(
        [property: JsonProperty("name", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("name")]
            string Name,
        [property: JsonProperty("desc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("desc")]
            string Description
    );

    internal record KeysetsInfo(
        [property: JsonProperty("keysets", Required = Required.Always)] [property: JsonPropertyName("keysets"), JsonRequired] KeysetInfo[] Keysets
    );

    internal record KeysetInfo(
        [property: JsonProperty("uuid", Required = Required.Always)] [property: JsonPropertyName("uuid"), JsonRequired] string Id,
        [property: JsonProperty("encryptedBy", Required = Required.Always)]
        [property: JsonPropertyName("encryptedBy"), JsonRequired]
            string EncryptedBy,
        [property: JsonProperty("sn", Required = Required.Always)] [property: JsonPropertyName("sn"), JsonRequired] int SerialNumber,
        [property: JsonProperty("encSymKey", Required = Required.Always)]
        [property: JsonPropertyName("encSymKey"), JsonRequired]
            KeyDerivationInfo KeyOrMasterKey,
        [property: JsonProperty("encPriKey", Required = Required.Always)] [property: JsonPropertyName("encPriKey"), JsonRequired] Encrypted PrivateKey
    );

    internal record AesKey(
        [property: JsonProperty("kid", Required = Required.Always)] [property: JsonPropertyName("kid"), JsonRequired] string Id,
        [property: JsonProperty("k", Required = Required.Always)] [property: JsonPropertyName("k"), JsonRequired] string Key
    );

    internal record RsaKey(
        [property: JsonProperty("kid", Required = Required.Always)] [property: JsonPropertyName("kid"), JsonRequired] string Id,
        [property: JsonProperty("e", Required = Required.Always)] [property: JsonPropertyName("e"), JsonRequired] string Exponent,
        [property: JsonProperty("n", Required = Required.Always)] [property: JsonPropertyName("n"), JsonRequired] string Modulus,
        [property: JsonProperty("p", Required = Required.Always)] [property: JsonPropertyName("p"), JsonRequired] string P,
        [property: JsonProperty("q", Required = Required.Always)] [property: JsonPropertyName("q"), JsonRequired] string Q,
        [property: JsonProperty("dp", Required = Required.Always)] [property: JsonPropertyName("dp"), JsonRequired] string DP,
        [property: JsonProperty("dq", Required = Required.Always)] [property: JsonPropertyName("dq"), JsonRequired] string DQ,
        [property: JsonProperty("qi", Required = Required.Always)] [property: JsonPropertyName("qi"), JsonRequired] string InverseQ,
        [property: JsonProperty("d", Required = Required.Always)] [property: JsonPropertyName("d"), JsonRequired] string D
    );

    // All these fields here are optional because for the master key and the master key only we have
    // more fields. For the master key these fields are not optional, but there's no way to express
    // this with attributes.
    internal record KeyDerivationInfo(
        string KeyId,
        string Scheme,
        string Container,
        string Iv,
        string Ciphertext,
        [property: JsonProperty("alg")] [property: JsonPropertyName("alg")] string Algorithm,
        [property: JsonProperty("p2s")] [property: JsonPropertyName("p2s")] string Salt,
        [property: JsonProperty("p2c")] [property: JsonPropertyName("p2c")] int Iterations
    ) : Encrypted(KeyId, Scheme, Container, Iv, Ciphertext);

    internal record VerifyKey(
        [property: JsonProperty("accountUuid", Required = Required.Always)]
        [property: JsonPropertyName("accountUuid"), JsonRequired]
            string AccountId,
        [property: JsonProperty("userUuid", Required = Required.Always)] [property: JsonPropertyName("userUuid"), JsonRequired] string UserId,
        [property: JsonProperty("serverVerifyHash", Required = Required.Always)]
        [property: JsonPropertyName("serverVerifyHash"), JsonRequired]
            string ServerHash,
        [property: JsonProperty("mfa")] [property: JsonPropertyName("mfa")] MfaInfo Mfa
    );

    internal record MfaInfo(
        [property: JsonProperty("dsecret")] [property: JsonPropertyName("dsecret")] BasicMfa RememberMe,
        [property: JsonProperty("totp")] [property: JsonPropertyName("totp")] BasicMfa GoogleAuth,
        [property: JsonProperty("webAuthn")] [property: JsonPropertyName("webAuthn")] WebAuthnMfa WebAuthn,
        [property: JsonProperty("duo")] [property: JsonPropertyName("duo")] DuoMfa Duo
    );

    internal record BasicMfa(
        [property: JsonProperty("enabled", Required = Required.Always)] [property: JsonPropertyName("enabled"), JsonRequired] bool Enabled
    );

    internal record WebAuthnMfa(
        bool Enabled,
        [property: JsonProperty("keyHandles")] [property: JsonPropertyName("keyHandles")] string[] KeyHandles,
        [property: JsonProperty("challenge")] [property: JsonPropertyName("challenge")] string Challenge
    ) : BasicMfa(Enabled);

    internal record DuoMfa(
        bool Enabled,
        // Cannot make these fields required in case they are not sent when Duo is disabled.
        // Need to check for validity later where they are being used.
        [property: JsonProperty("host")]
        [property: JsonPropertyName("host")]
            string Host,
        [property: JsonProperty("sigRequest")] [property: JsonPropertyName("sigRequest")] string Signature,
        [property: JsonProperty("authURL")] [property: JsonPropertyName("authURL")] string Url
    ) : BasicMfa(Enabled);

    internal record Error(
        [property: JsonProperty("errorCode", Required = Required.Always)] [property: JsonPropertyName("errorCode"), JsonRequired] int Code,
        [property: JsonProperty("errorMessage", Required = Required.Always)] [property: JsonPropertyName("errorMessage"), JsonRequired] string Message
    );

    internal record FailureReason(
        [property: JsonProperty("reason", Required = Required.Always)] [property: JsonPropertyName("reason"), JsonRequired] string Reason
    );

    internal record Mfa(
        [property: JsonProperty("dsecret", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("dsecret")]
            string RememberMeToken
    );

    internal record VaultItemsBatch(
        [property: JsonProperty("contentVersion", Required = Required.Always)]
        [property: JsonPropertyName("contentVersion"), JsonRequired]
            int Version,
        [property: JsonProperty("items")] [property: JsonPropertyName("items")] VaultItem[] Items,
        [property: JsonProperty("batchComplete", Required = Required.Always)]
        [property: JsonPropertyName("batchComplete"), JsonRequired]
            bool Complete
    );

    internal record SingleVaultItem(
        [property: JsonProperty("contentVersion", Required = Required.Always)]
        [property: JsonPropertyName("contentVersion"), JsonRequired]
            int Version,
        [property: JsonProperty("item", Required = Required.Always)] [property: JsonPropertyName("item"), JsonRequired] VaultItem Item
    );

    internal record VaultItem(
        [property: JsonProperty("uuid", Required = Required.Always)] [property: JsonPropertyName("uuid"), JsonRequired] string Id,
        [property: JsonProperty("templateUuid", Required = Required.Always)]
        [property: JsonPropertyName("templateUuid"), JsonRequired]
            string TemplateId,
        [property: JsonProperty("trashed", Required = Required.Always)] [property: JsonPropertyName("trashed"), JsonRequired] string Deleted,
        [property: JsonProperty("itemVersion", Required = Required.Always)] [property: JsonPropertyName("itemVersion"), JsonRequired] int Version,
        [property: JsonProperty("encryptedBy", Required = Required.Always)]
        [property: JsonPropertyName("encryptedBy"), JsonRequired]
            string EncryptedBy,
        [property: JsonProperty("encOverview", Required = Required.Always)]
        [property: JsonPropertyName("encOverview"), JsonRequired]
            Encrypted Overview,
        [property: JsonProperty("encDetails", Required = Required.Always)] [property: JsonPropertyName("encDetails"), JsonRequired] Encrypted Details
    );

    internal record VaultItemOverview(
        [property: JsonProperty("title")] [property: JsonPropertyName("title")] string Title,
        [property: JsonProperty("ainfo")] [property: JsonPropertyName("ainfo")] string AdditionalInfo,
        [property: JsonProperty("url")] [property: JsonPropertyName("url")] string Url,
        [property: JsonProperty("URLs")] [property: JsonPropertyName("URLs")] VaultItemUrl[] Urls
    );

    internal record VaultItemUrl(
        [property: JsonProperty("l", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("l")]
            string Name,
        [property: JsonProperty("u", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("u")]
            string Url
    );

    internal record VaultItemDetails(
        [property: JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("title")]
            string Name,
        [property: JsonProperty("url", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("url")]
            string Url,
        [property: JsonProperty("notesPlain", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("notesPlain")]
            string Note,
        [property: JsonProperty("fields")] [property: JsonPropertyName("fields")] VaultItemField[] Fields,
        [property: JsonProperty("sections")] [property: JsonPropertyName("sections")] VaultItemSection[] Sections
    );

    internal record VaultItemField(
        [property: JsonProperty("designation", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("designation")]
            string Designation,
        [property: JsonProperty("value", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("value")]
            string Value
    );

    internal record VaultItemSection(
        [property: JsonProperty("title", DefaultValueHandling = DefaultValueHandling.Populate)]
        [property: DefaultValue("")]
        [property: JsonPropertyName("title")]
            string Name,
        [property: JsonProperty("fields")] [property: JsonPropertyName("fields")] VaultItemSectionField[] Fields
    );

    internal record VaultItemSectionField(
        [property: JsonProperty("n")] [property: JsonPropertyName("n")] string Id,
        [property: JsonProperty("t")] [property: JsonPropertyName("t")] string Name,
        [property: Newtonsoft.Json.JsonConverter(typeof(VaultItemSectionFieldValueConverter))]
        [property: JsonProperty("v")]
        [property: JsonPropertyName("v")]
            string Value,
        [property: JsonProperty("k")] [property: JsonPropertyName("k")] string Kind,
        [property: JsonProperty("a")] [property: JsonPropertyName("a")] VaultItemFieldAttributes Attributes
    );

    internal record VaultItemFieldAttributes(
        [property: JsonProperty("guarded")] [property: JsonPropertyName("guarded")] string Guarded,
        [property: JsonProperty("sshKeyAttributes")] [property: JsonPropertyName("sshKeyAttributes")] SshKeyAttributes SshKey
    );

    internal record SshKeyAttributes(
        [property: JsonProperty("privateKey")] [property: JsonPropertyName("privateKey")] string PrivateKey,
        [property: JsonProperty("publicKey")] [property: JsonPropertyName("publicKey")] string PublicKey,
        [property: JsonProperty("fingerprint")] [property: JsonPropertyName("fingerprint")] string Fingerprint,
        [property: JsonProperty("keyType")] [property: JsonPropertyName("keyType")] SshKeyType KeyType
    );

    internal record SshKeyType(
        [property: JsonProperty("t")] [property: JsonPropertyName("t")] string Type,
        [property: JsonProperty("c")] [property: JsonPropertyName("c")] int Bits
    );

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

    internal record AForBV1(
        [property: JsonProperty("sessionID", Required = Required.Always)] [property: JsonPropertyName("sessionID"), JsonRequired] string SessionId,
        [property: JsonProperty("userB", Required = Required.Always)] [property: JsonPropertyName("userB"), JsonRequired] string B
    );

    //
    // SrpV2
    //

    internal record AForBV2([property: JsonPropertyName("userB"), JsonRequired] string B);

    internal record ServerHash([property: JsonPropertyName("serverVerifyHash"), JsonRequired] string ServerVerifyHash);

    internal record ServiceAccountToken(
        [property: JsonProperty("signInAddress")] [property: JsonPropertyName("signInAddress")] string Domain,
        [property: JsonProperty("email")] [property: JsonPropertyName("email")] string Username,
        [property: JsonProperty("secretKey")] [property: JsonPropertyName("secretKey")] string AccountKey,
        [property: JsonProperty("deviceUuid")] [property: JsonPropertyName("deviceUuid")] string DeviceUuid,
        [property: JsonProperty("srpX")] [property: JsonPropertyName("srpX")] string SrpX,
        [property: JsonProperty("muk")] [property: JsonPropertyName("muk")] AesKey MasterUnlockKey
    );
}
