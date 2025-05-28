// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace PasswordManagerAccess.OnePassword;

// TODO: Merge with Response
[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")] // The classes here are used for deserialization only
internal static class Model
{
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
        [property: JsonPropertyName("encCredentials")] Response.Encrypted EncryptedCredentials,
        [property: JsonPropertyName("v")] int Version,
        [property: JsonPropertyName("accountKeyFormat")] string AccountKeyFormat,
        [property: JsonPropertyName("accountKeyUuid")] string AccountKeyUuid,
        [property: JsonPropertyName("userAuth")] Response.UserAuth UserAuth
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

    public record SsoCredentials([property: JsonPropertyName("encCreds")] Response.Encrypted EncryptedCredentials);

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
