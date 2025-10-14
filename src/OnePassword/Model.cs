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
    internal record UserLoginInfo
    {
        [JsonPropertyName("userUuid")]
        public required string UserUuid { get; init; }

        [JsonPropertyName("signInAddress")]
        public required string Url { get; init; }
    }

    internal record NewSession
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

    internal record UserAuth
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

    internal record struct SuccessStatus
    {
        [JsonPropertyName("success")]
        public required int Success { get; init; }
    }

    internal record Encrypted
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
        // Optional, as this field can be null
        [JsonPropertyName("name")]
        public string? Name { get; init; }

        // Optional, as this field can be null
        [JsonPropertyName("desc")]
        public string? Description { get; init; }
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

    internal record KeyDerivationInfo : Encrypted
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

    internal record VerifyKey
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
    internal record MfaInfo
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

    internal record BasicMfa
    {
        [JsonPropertyName("enabled")]
        public required bool Enabled { get; init; }
    }

    internal record WebAuthnMfa : BasicMfa
    {
        // Optional, as it's only present if WebAuthn is enabled
        [JsonPropertyName("keyHandles")]
        public string[]? KeyHandles { get; init; }

        // Optional, as it's only present if WebAuthn is enabled
        [JsonPropertyName("challenge")]
        public string? Challenge { get; init; }
    }

    internal record DuoMfa : BasicMfa
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
        [JsonPropertyName("dsecret")]
        public required string RememberMeToken { get; init; }
    }

    internal record VaultItemsBatch
    {
        [JsonPropertyName("contentVersion")]
        public required int Version { get; init; }

        [JsonPropertyName("batchComplete")]
        public required bool Complete { get; init; }

        // Optional, as it can be null for an empty batch
        [JsonPropertyName("items")]
        public VaultItem[]? Items { get; init; }
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

    internal record VaultItemUrl
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("l")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("u")]
        public string? Url { get; init; }
    }

    internal record VaultItemDetails
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

    internal record VaultItemField
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("designation")]
        public string? Designation { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("value")]
        public string? Value { get; init; }
    }

    internal record VaultItemSection
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("title")]
        public string? Name { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("fields")]
        public VaultItemSectionField[]? Fields { get; init; }
    }

    internal record VaultItemSectionField
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

    internal record VaultItemFieldAttributes
    {
        // Optional, as this field can be null or missing
        [JsonPropertyName("guarded")]
        public string? Guarded { get; init; }

        // Optional, as this field can be null or missing
        [JsonPropertyName("sshKeyAttributes")]
        public SshKeyAttributes? SshKey { get; init; }
    }

    internal record SshKeyAttributes
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

    internal record SshKeyType
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

    public record LoginInfo(
        [property: JsonPropertyName("userUuid")] string UserUuid,
        [property: JsonPropertyName("signInAddress")] string SignInAddress,
        [property: JsonPropertyName("authMethods")] AuthMethod[] AuthMethods
    );

    public record AuthMethod(
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("provider")] string Provider,
        [property: JsonPropertyName("iconUrl")] string IconUrl
    );

    //
    // Response from v3/auth/sso/oidc/start
    //

    public record SsoLoginUrl([property: JsonPropertyName("authRedirect")] string OidcUrl);

    //
    // Response from v3/auth/sso/oidc/verify
    //

    public record SsoSession(
        [property: JsonPropertyName("type")] string State,
        [property: JsonPropertyName("user")] SsoUser User,
        [property: JsonPropertyName("auth")] Auth Auth,
        [property: JsonPropertyName("ssoAuth")] SsoAuth SsoAuth
    );

    public record SsoUser(
        [property: JsonPropertyName("sessionUuid")] string SessionUuid,
        [property: JsonPropertyName("accountUuid")] string AccountUuid,
        [property: JsonPropertyName("userUuid")] string UserUuid,
        [property: JsonPropertyName("email")] string Email
    );

    public record Auth(
        [property: JsonPropertyName("encCredentials")] Encrypted EncryptedCredentials,
        [property: JsonPropertyName("v")] int Version,
        [property: JsonPropertyName("accountKeyFormat")] string AccountKeyFormat,
        [property: JsonPropertyName("accountKeyUuid")] string AccountKeyUuid,
        [property: JsonPropertyName("userAuth")] UserAuth UserAuth
    );

    public record SsoAuth([property: JsonPropertyName("signInTokenDetails")] SignInTokenDetails SignInTokenDetails);

    public record SignInTokenDetails(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("publicKey")] string PublicKey,
        [property: JsonPropertyName("exp")] string ExpiresAt
    );

    //
    // Response from v3/device/enrollments
    //

    public record SsoEnrollInfo(
        [property: JsonPropertyName("enrollmentUuid")] string EnrollmentUuid,
        [property: JsonPropertyName("accountKeyUuid")] string AccountKeyUuid
    );

    //
    // Response from v3/device/enrollments/status
    //

    public record SsoEnrollStatus([property: JsonPropertyName("status")] string Status);

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/msga
    //

    public record CpaceMsgA([property: JsonPropertyName("msga")] string MsgA);

    //
    // Encoded inside CpaceMsgA.MsgA
    //

    public record MsgA([property: JsonPropertyName("ya")] string Ya, [property: JsonPropertyName("ad")] Ad Ad);

    public record Ad(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("salt")] string Salt,
        [property: JsonPropertyName("session_id")] int[] SessionId
    );

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/msgb
    //

    public record SuccessResult([property: JsonPropertyName("success")] int Success);

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/cpace/taga
    //

    public record CpaceTagA([property: JsonPropertyName("taga")] string TagA);

    //
    // Response from v3/device/enrollments/{enrollmentUuid}/share/credentials
    //

    public record SsoCredentials([property: JsonPropertyName("encCreds")] Encrypted EncryptedCredentials);

    //
    // Encoded inside SsoCredentials.EncryptedCredentials
    //

    public record CredentialBundle([property: JsonPropertyName("srpx")] string SrpX, [property: JsonPropertyName("auk")] Auk Auk);

    public record Auk(
        [property: JsonPropertyName("alg")] string Algorithm,
        [property: JsonPropertyName("k")] string Key,
        [property: JsonPropertyName("kty")] string KeyType,
        [property: JsonPropertyName("kid")] string KeyId
    );

    //
    // Response from v2/auth/complete
    //

    public record AuthComplete(
        [property: JsonPropertyName("notifier")] string Notifier,
        [property: JsonPropertyName("accountUuid")] string AccountUuid,
        [property: JsonPropertyName("userUuid")] string UserUuid
    );

    //
    // Storage models
    //

    internal record DeviceKeyDerivation(
        [property: JsonPropertyName("kid")] string Id,
        [property: JsonPropertyName("k")] string Key,
        [property: JsonPropertyName("s")] string Salt
    );
}
