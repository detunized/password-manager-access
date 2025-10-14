// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

// The classes here are used for [de]serialization only
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PasswordManagerAccess.OnePassword;

internal static class Model
{
    // TODO: Review what's required and what isn't
    public record UserLoginInfo
    {
        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonPropertyName("signInAddress")]
        public required string Url { get; init; }
    }

    public record NewSession
    {
        [JsonPropertyName("status")]
        public required string Status { get; init; }

        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        // Optional, as it's only used with the session is "ok"
        [JsonPropertyName("accountKeyFormat")]
        public string? KeyFormat { get; init; }

        // Optional, as it's only used with the session is "ok"
        [JsonPropertyName("accountKeyUuid")]
        public string? KeyUuid { get; init; }

        // Optional, as it's only used with the session is "ok"
        [JsonPropertyName("userAuth")]
        public UserAuth? Auth { get; init; }
    }

    public record UserAuth
    {
        [JsonPropertyName("method")]
        public required string Method { get; init; }

        [JsonPropertyName("alg")]
        public required string Algorithm { get; init; }

        [JsonPropertyName("iterations")]
        public required int Iterations { get; init; }

        [JsonPropertyName("salt")]
        public required string Salt { get; init; }
    }

    public record struct SuccessStatus
    {
        [JsonPropertyName("success")]
        public required int Success { get; init; }
    }

    public record Encrypted
    {
        [JsonPropertyName("kid")]
        public required string KeyId { get; init; }

        [JsonPropertyName("enc")]
        public required string Scheme { get; init; }

        [JsonPropertyName("cty")]
        public required string Container { get; init; }

        // Optional, as not all encryption schemes use an IV
        [JsonPropertyName("iv")]
        public string? Iv { get; init; }

        [JsonPropertyName("data")]
        public required string Ciphertext { get; init; }
    }

    public record AccountInfo
    {
        [JsonPropertyName("me")]
        public required MeInfo Me { get; init; }

        [JsonPropertyName("vaults")]
        public required VaultInfo[] Vaults { get; init; }
    }

    public record MeInfo
    {
        [JsonPropertyName("vaultAccess")]
        public required VaultAccessInfo[] VaultAccess { get; init; }
    }

    public record VaultAccessInfo
    {
        [JsonPropertyName("vaultUuid")]
        public required string Id { get; init; }

        [JsonPropertyName("acl")]
        public required int Acl { get; init; }

        [JsonPropertyName("encVaultKey")]
        public required Encrypted EncryptedKey { get; init; }
    }

    public record VaultInfo
    {
        [JsonPropertyName("uuid")]
        public required string Id { get; init; }

        [JsonPropertyName("encAttrs")]
        public required Encrypted Attributes { get; init; }

        [JsonPropertyName("access")]
        public required VaultAccessInfo[] Access { get; init; }
    }

    public record VaultAttributes
    {
        // Optional, as this field can be null
        [JsonPropertyName("name")]
        public string? Name { get; init; }

        // Optional, as this field can be null
        [JsonPropertyName("desc")]
        public string? Description { get; init; }
    }

    public record KeysetsInfo
    {
        [JsonPropertyName("keysets")]
        public required KeysetInfo[] Keysets { get; init; }
    }

    public record KeysetInfo
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

    public record KeyDerivationInfo : Encrypted
    {
        // Optional, as this field is only present for the master key, otherwise it's null or missing
        [JsonPropertyName("alg")]
        public string? Algorithm { get; init; }

        // Optional, as this field is only present for the master key, otherwise it's null or missing
        [JsonPropertyName("p2s")]
        public string? Salt { get; init; }

        // Optional, as this field is only present for the master key, otherwise it's null or missing
        [JsonPropertyName("p2c")]
        public int Iterations { get; init; }
    }

    public record AesKey
    {
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonPropertyName("k")]
        public required string Key { get; init; }
    }

    public record RsaKey
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

    public record VerifyKey
    {
        [JsonPropertyName("accountUuid")]
        public required string AccountId { get; init; }

        [JsonPropertyName("userUuid")]
        public required string UserId { get; init; }

        [JsonPropertyName("serverVerifyHash")]
        public required string ServerHash { get; init; }

        // Optional, as it's only present if MFA is enabled
        [JsonPropertyName("mfa")]
        public MfaInfo? Mfa { get; init; }
    }

    // All fields are optional, as it's essentially a union type
    public record MfaInfo
    {
        [JsonPropertyName("dsecret")]
        public BasicMfa? RememberMe { get; init; }

        [JsonPropertyName("totp")]
        public BasicMfa? GoogleAuth { get; init; }

        [JsonPropertyName("webAuthn")]
        public WebAuthnMfa? WebAuthn { get; init; }

        [JsonPropertyName("duo")]
        public DuoMfa? Duo { get; init; }
    }

    public record BasicMfa
    {
        [JsonPropertyName("enabled")]
        public required bool Enabled { get; init; }
    }

    public record WebAuthnMfa : BasicMfa
    {
        // Optional, as it's only present if WebAuthn is enabled
        [JsonPropertyName("keyHandles")]
        public string[]? KeyHandles { get; init; }

        // Optional, as it's only present if WebAuthn is enabled
        [JsonPropertyName("challenge")]
        public string? Challenge { get; init; }

        // Optional, as it's only present if WebAuthn is enabled
        [JsonPropertyName("rpid")]
        public string? RpId { get; init; }
    }

    public record DuoMfa : BasicMfa
    {
        // Optional, as it's only present if Duo is enabled
        [JsonPropertyName("host")]
        public string? Host { get; init; }

        // Optional, as it's only present if Duo is enabled
        [JsonPropertyName("sigRequest")]
        public string? Signature { get; init; }

        // Optional, as it's only present if Duo V4 is enabled
        [JsonPropertyName("authURL")]
        public string? Url { get; init; }
    }

    public record Error
    {
        [JsonPropertyName("errorCode")]
        public required int Code { get; init; }

        [JsonPropertyName("errorMessage")]
        public required string Message { get; init; }
    }

    public record FailureReason
    {
        [JsonPropertyName("reason")]
        public required string Reason { get; init; }
    }

    public record Mfa
    {
        [JsonPropertyName("dsecret")]
        public required string RememberMeToken { get; init; }
    }

    public record VaultItemsBatch
    {
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("batchComplete")]
        public required bool Complete { get; init; }

        // Optional, as it can be null for an empty batch
        [JsonPropertyName("items")]
        public VaultItem[]? Items { get; init; }
    }

    public record SingleVaultItem
    {
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("item")]
        public required VaultItem Item { get; init; }
    }

    public record VaultItem
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

    public record VaultItemOverview
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("title")]
        public string? Title { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("ainfo")]
        public string? AdditionalInfo { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("url")]
        public string? Url { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("URLs")]
        public VaultItemUrl[]? Urls { get; init; }
    }

    public record VaultItemUrl
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("l")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("u")]
        public string? Url { get; init; }
    }

    public record VaultItemDetails
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("title")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("url")]
        public string? Url { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("notesPlain")]
        public string? Note { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("fields")]
        public VaultItemField[]? Fields { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("sections")]
        public VaultItemSection[]? Sections { get; init; }
    }

    public record VaultItemField
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("designation")]
        public string? Designation { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("value")]
        public string? Value { get; init; }
    }

    public record VaultItemSection
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("title")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("fields")]
        public VaultItemSectionField[]? Fields { get; init; }
    }

    public record VaultItemSectionField
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("n")]
        public string? Id { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("t")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("v")]
        [JsonConverter(typeof(VaultItemSectionFieldValueConverter))]
        public string? Value { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("k")]
        public string? Kind { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("a")]
        public VaultItemFieldAttributes? Attributes { get; init; }
    }

    public record VaultItemFieldAttributes
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("guarded")]
        public string? Guarded { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("sshKeyAttributes")]
        public SshKeyAttributes? SshKey { get; init; }
    }

    public record SshKeyAttributes
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("privateKey")]
        public string? PrivateKey { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("publicKey")]
        public string? PublicKey { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("fingerprint")]
        public string? Fingerprint { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("keyType")]
        public SshKeyType? KeyType { get; init; }
    }

    public record SshKeyType
    {
        [JsonPropertyName("t")]
        public required string Type { get; init; }

        // Optional, as this field is only present for RSA keys
        [JsonPropertyName("c")]
        public int Bits { get; init; }
    }

    // The "v" value could be practically anything. We are only interested in the string values.
    // The rest is simply converted to JSON as a fallback.
    internal class VaultItemSectionFieldValueConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            // Read the entire value as a JsonElement first
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var element = jsonDoc.RootElement;

            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                _ => element.GetRawText(),
            };
        }

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) => throw new NotImplementedException();
    }

    //
    // SrpV1
    //

    public record AForBv1
    {
        [JsonPropertyName("sessionID")]
        public required string SessionId { get; init; }

        [JsonPropertyName("userB")]
        public required string B { get; init; }
    }

    //
    // SrpV2
    //

    public record AForBv2
    {
        [JsonPropertyName("userB")]
        public required string B { get; init; }
    }

    public record ServerHash
    {
        [JsonPropertyName("serverVerifyHash")]
        public required string ServerVerifyHash { get; init; }
    }

    public record ServiceAccountToken
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("signInAddress")]
        public string? Domain { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("email")]
        public string? Username { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("secretKey")]
        public string? AccountKey { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("deviceUuid")]
        public string? DeviceUuid { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("srpX")]
        public string? SrpX { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("muk")]
        public AesKey? MasterUnlockKey { get; init; }
    }

    //
    // Response from v2/auth/methods
    //

    public record LoginInfo
    {
        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonPropertyName("signInAddress")]
        public required string SignInAddress { get; init; }

        [JsonPropertyName("authMethods")]
        public required AuthMethod[] AuthMethods { get; init; }
    }

    public record AuthMethod
    {
        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("provider")]
        public required string Provider { get; init; }

        [JsonPropertyName("iconUrl")]
        public required string IconUrl { get; init; }
    }

    //
    // Response from v3/auth/sso/oidc/start
    //

    public record SsoLoginUrl
    {
        [JsonPropertyName("authRedirect")]
        public required string OidcUrl { get; init; }
    }

    //
    // Response from v3/auth/sso/oidc/verify
    //

    public record SsoSession
    {
        [JsonPropertyName("type")]
        public required string State { get; init; }

        [JsonPropertyName("user")]
        public required SsoUser User { get; init; }

        [JsonPropertyName("auth")]
        public required Auth Auth { get; init; }

        [JsonPropertyName("ssoAuth")]
        public required SsoAuth SsoAuth { get; init; }
    }

    public record SsoUser
    {
        [JsonPropertyName("sessionUuid")]
        public required string SessionUuid { get; init; }

        [JsonPropertyName("accountUuid")]
        public required string AccountUuid { get; init; }

        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonPropertyName("email")]
        public required string Email { get; init; }
    }

    public record Auth
    {
        [JsonPropertyName("encCredentials")]
        public required Encrypted EncryptedCredentials { get; init; }

        [JsonPropertyName("v")]
        public required int Version { get; init; }

        [JsonPropertyName("accountKeyFormat")]
        public required string AccountKeyFormat { get; init; }

        [JsonPropertyName("accountKeyUuid")]
        public required string AccountKeyUuid { get; init; }

        [JsonPropertyName("userAuth")]
        public required UserAuth UserAuth { get; init; }
    }

    public record SsoAuth
    {
        [JsonPropertyName("signInTokenDetails")]
        public required SignInTokenDetails SignInTokenDetails { get; init; }
    }

    public record SignInTokenDetails
    {
        [JsonPropertyName("token")]
        public required string Token { get; init; }

        [JsonPropertyName("publicKey")]
        public required string PublicKey { get; init; }

        [JsonPropertyName("exp")]
        public required string ExpiresAt { get; init; }
    }

    //
    // Response from v3/device/enrollments
    //

    public record SsoEnrollInfo
    {
        [JsonPropertyName("enrollmentUuid")]
        public required string EnrollmentUuid { get; init; }

        [JsonPropertyName("accountKeyUuid")]
        public required string AccountKeyUuid { get; init; }
    }

    //
    // Response from v3/device/enrollments/status
    //

    public record SsoEnrollStatus
    {
        [JsonPropertyName("status")]
        public required string Status { get; init; }
    }

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/msga
    //

    public record CpaceMsgA
    {
        [JsonPropertyName("msga")]
        public required string MsgA { get; init; }
    }

    //
    // Encoded inside CpaceMsgA.MsgA
    //

    public record MsgA
    {
        [JsonPropertyName("ya")]
        public required string Ya { get; init; }

        [JsonPropertyName("ad")]
        public required Ad Ad { get; init; }
    }

    public record Ad
    {
        [JsonPropertyName("version")]
        public required int Version { get; init; }

        [JsonPropertyName("salt")]
        public required string Salt { get; init; }

        [JsonPropertyName("session_id")]
        public required int[] SessionId { get; init; }
    }

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/msgb
    //

    public record SuccessResult
    {
        [JsonPropertyName("success")]
        public required int Success { get; init; }
    }

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/taga
    //

    public record CpaceTagA
    {
        [JsonPropertyName("taga")]
        public required string TagA { get; init; }
    }

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/share/credentials
    //

    public record SsoCredentials
    {
        [JsonPropertyName("encCreds")]
        public required Encrypted EncryptedCredentials { get; init; }
    }

    //
    // Encoded inside SsoCredentials.EncryptedCredentials
    //

    public record CredentialBundle
    {
        [JsonPropertyName("srpx")]
        public required string SrpX { get; init; }

        [JsonPropertyName("auk")]
        public required Auk Auk { get; init; }
    }

    public record Auk
    {
        [JsonPropertyName("alg")]
        public required string Algorithm { get; init; }

        [JsonPropertyName("k")]
        public required string Key { get; init; }

        [JsonPropertyName("kty")]
        public required string KeyType { get; init; }

        [JsonPropertyName("kid")]
        public required string KeyId { get; init; }
    }

    //
    // Response from v2/auth/complete
    //

    public record AuthComplete
    {
        [JsonPropertyName("notifier")]
        public required string Notifier { get; init; }

        [JsonPropertyName("accountUuid")]
        public required string AccountUuid { get; init; }

        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }
    }

    //
    // Storage models
    //

    public record DeviceKeyDerivation
    {
        [JsonPropertyName("kid")]
        public required string Id { get; init; }

        [JsonPropertyName("k")]
        public required string Key { get; init; }

        [JsonPropertyName("s")]
        public required string Salt { get; init; }
    }
}
