// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Text.Json.Serialization;

// All the models here are used in deserialization and are not supposed to be instantiated directly.
// ReSharper disable ClassNeverInstantiated.Global

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Model
    {
        public class Response
        {
            [JsonPropertyName("Code")]
            [JsonRequired]
            public int Code { get; set; }
        }

        public class Error : Response
        {
            [JsonPropertyName("Error")]
            [JsonRequired]
            public string? Text { get; set; }

            [JsonPropertyName("Details")]
            public ErrorDetails? Details { get; set; }
        }

        // Everything must be optional in this class
        public class ErrorDetails
        {
            [JsonPropertyName("HumanVerificationToken")]
            public string? HumanVerificationToken { get; set; }

            [JsonPropertyName("HumanVerificationMethods")]
            public string[]? HumanVerificationMethods { get; set; }

            [JsonPropertyName("MissingScopes")]
            public string[]? MissingScopes { get; set; }

            [JsonPropertyName("Direct")]
            public int Direct { get; set; }

            [JsonPropertyName("Description")]
            public string? Description { get; set; }

            [JsonPropertyName("Title")]
            public string? Title { get; set; }

            [JsonPropertyName("WebUrl")]
            public string? Url { get; set; }

            [JsonPropertyName("ExpiresAt")]
            public int ExpiresAt { get; set; }
        }

        public class Session : Response
        {
            [JsonPropertyName("AccessToken")]
            [JsonRequired]
            public string AccessToken { get; set; } = "";

            [JsonPropertyName("RefreshToken")]
            [JsonRequired]
            public string RefreshToken { get; set; } = "";

            [JsonPropertyName("TokenType")]
            [JsonRequired]
            public string TokenType { get; set; } = "";

            [JsonPropertyName("Scopes")]
            public object[]? Scopes { get; set; }

            [JsonPropertyName("UID")]
            [JsonRequired]
            public string Id { get; set; } = "";

            [JsonPropertyName("LocalID")]
            public int LocalId { get; set; }
        }

        internal class AuthInfo : Response
        {
            [JsonPropertyName("Modulus")]
            [JsonRequired]
            public string Modulus { get; set; } = "";

            [JsonPropertyName("ServerEphemeral")]
            [JsonRequired]
            public string ServerEphemeral { get; set; } = "";

            [JsonPropertyName("Version")]
            public int Version { get; set; }

            [JsonPropertyName("Salt")]
            [JsonRequired]
            public string Salt { get; set; } = "";

            [JsonPropertyName("SRPSession")]
            [JsonRequired]
            public string SrpSession { get; set; } = "";

            [JsonPropertyName("Username")]
            public string Username { get; set; } = "";
        }

        internal class ExtraAuthInfo : Response
        {
            [JsonPropertyName("SRPData")]
            [JsonRequired]
            public SrpData SrpData { get; set; } = new();
        }

        internal class SrpData
        {
            [JsonPropertyName("Modulus")]
            [JsonRequired]
            public string Modulus { get; set; } = "";

            [JsonPropertyName("ServerEphemeral")]
            [JsonRequired]
            public string ServerEphemeral { get; set; } = "";

            [JsonPropertyName("SrpSessionID")]
            [JsonRequired]
            public string SessionId { get; set; } = "";

            [JsonPropertyName("SrpSalt")]
            [JsonRequired]
            public string Salt { get; set; } = "";

            [JsonPropertyName("Version")]
            public int Version { get; set; }
        }

        public class Auth : Response
        {
            [JsonPropertyName("LocalID")]
            public int LocalId { get; set; }

            [JsonPropertyName("TokenType")]
            [JsonRequired]
            public string TokenType { get; set; } = "";

            [JsonPropertyName("AccessToken")]
            [JsonRequired]
            public string AccessToken { get; set; } = "";

            [JsonPropertyName("RefreshToken")]
            [JsonRequired]
            public string RefreshToken { get; set; } = "";

            [JsonPropertyName("Scopes")]
            public string[] Scopes { get; set; } = [];

            [JsonPropertyName("UID")]
            [JsonRequired]
            public string SessionId { get; set; } = "";

            [JsonPropertyName("UserID")]
            public string UserId { get; set; } = "";

            [JsonPropertyName("EventID")]
            public string EventId { get; set; } = "";

            [JsonPropertyName("PasswordMode")]
            public int PasswordMode { get; set; }

            [JsonPropertyName("ServerProof")]
            [JsonRequired]
            public string ServerProof { get; set; } = "";

            [JsonPropertyName("Scope")]
            public string Scope { get; set; } = "";

            [JsonPropertyName("TwoFactor")]
            public int TwoFactor { get; set; }

            [JsonPropertyName("2FA")]
            public Mfa Mfa { get; set; }

            [JsonPropertyName("TemporaryPassword")]
            public int TemporaryPassword { get; set; }
        }

        public struct Mfa
        {
            [JsonPropertyName("Enabled")]
            public int Enabled { get; set; }

            [JsonPropertyName("TOTP")]
            public int Totp { get; set; }

            [JsonPropertyName("FIDO2")]
            public Fido2 Fido2 { get; set; }
        }

        public struct Fido2
        {
            [JsonPropertyName("AuthenticationOptions")]
            public Fido2Options? AuthenticationOptions { get; set; }

            [JsonPropertyName("RegisteredKeys")]
            public Fido2Key[] RegisteredKeys { get; set; }
        }

        public struct Fido2Options
        {
            [JsonPropertyName("publicKey")]
            public Fido2PublicKey PublicKey { get; set; }
        }

        public struct Fido2PublicKey
        {
            [JsonPropertyName("timeout")]
            public int Timeout { get; set; }

            [JsonPropertyName("challenge")]
            public int[] Challenge { get; set; }

            [JsonPropertyName("userVerification")]
            public string UserVerification { get; set; }

            [JsonPropertyName("rpId")]
            public string RpId { get; set; }

            [JsonPropertyName("allowCredentials")]
            public Fido2Credentials[] AllowCredentials { get; set; }
        }

        public struct Fido2Credentials
        {
            [JsonPropertyName("id")]
            public int[] Id { get; set; }

            [JsonPropertyName("type")]
            public string Type { get; set; }
        }

        public struct Fido2Key
        {
            [JsonPropertyName("Name")]
            public string Name { get; set; }

            [JsonPropertyName("AttestationFormat")]
            public string AttestationFormat { get; set; }

            [JsonPropertyName("CredentialID")]
            public int[] CredentialId { get; set; }
        }

        public class UserResponse : Response
        {
            [JsonPropertyName("User")]
            [JsonRequired]
            public User User { get; set; } = new();
        }

        public class User
        {
            [JsonPropertyName("ID")]
            [JsonRequired]
            public string Id { get; set; } = "";

            [JsonPropertyName("Keys")]
            [JsonRequired]
            public UserKey[] Keys { get; set; } = [];
        }

        public class UserKey
        {
            [JsonPropertyName("ID")]
            [JsonRequired]
            public string Id { get; set; } = "";

            [JsonPropertyName("Version")]
            public int Version { get; set; }

            [JsonPropertyName("Primary")]
            public int Primary { get; set; }

            [JsonPropertyName("PrivateKey")]
            public string PrivateKey { get; set; } = "";

            [JsonPropertyName("Fingerprint")]
            public string Fingerprint { get; set; } = "";

            [JsonPropertyName("Active")]
            public int Active { get; set; }
        }

        public class SaltsResponse : Response
        {
            [JsonPropertyName("KeySalts")]
            [JsonRequired]
            public KeySalt[] KeySalts { get; set; } = [];
        }

        public class KeySalt
        {
            [JsonPropertyName("ID")]
            [JsonRequired]
            public string Id { get; set; } = "";

            [JsonPropertyName("KeySalt")]
            public string? Salt { get; set; }
        }

        public class AllShares : Response
        {
            [JsonPropertyName("Shares")]
            public Share[] Shares { get; set; } = [];
        }

        public class SingleShare : Response
        {
            [JsonPropertyName("Share")]
            public Share Share { get; set; }
        }

        public class Share
        {
            [JsonPropertyName("ShareID")]
            public string Id { get; set; } = "";

            [JsonPropertyName("VaultID")]
            public string VaultId { get; set; } = "";

            [JsonPropertyName("AddressID")]
            public string AddressId { get; set; } = "";

            [JsonPropertyName("Primary")]
            public bool Primary { get; set; }

            [JsonPropertyName("Owner")]
            public bool Owner { get; set; }

            [JsonPropertyName("TargetType")]
            public int TargetType { get; set; }

            [JsonPropertyName("TargetID")]
            public string TargetId { get; set; } = "";

            [JsonPropertyName("TargetMembers")]
            public int TargetMembers { get; set; }

            [JsonPropertyName("TargetMaxMembers")]
            public int TargetMaxMembers { get; set; }

            [JsonPropertyName("Shared")]
            public bool Shared { get; set; }

            [JsonPropertyName("ShareRoleID")]
            public string ShareRoleId { get; set; } = "";

            [JsonPropertyName("Content")]
            public string Content { get; set; } = "";

            [JsonPropertyName("ContentKeyRotation")]
            public int ContentKeyRotation { get; set; }

            [JsonPropertyName("ContentFormatVersion")]
            public int ContentFormatVersion { get; set; }
        }

        public class ShareKeysRoot : Response
        {
            [JsonPropertyName("ShareKeys")]
            public ShareKeys ShareKeys { get; set; } = new();
        }

        public class ShareKeys
        {
            [JsonPropertyName("Keys")]
            public ShareKey[] Keys { get; set; } = [];

            [JsonPropertyName("Total")]
            public int Total { get; set; }
        }

        public class ShareKey
        {
            [JsonPropertyName("KeyRotation")]
            public int KeyRotation { get; set; }

            [JsonPropertyName("Key")]
            public string Key { get; set; } = "";

            [JsonPropertyName("UserKeyID")]
            public string UserKeyId { get; set; } = "";

            [JsonPropertyName("CreateTime")]
            public int CreateTime { get; set; }
        }

        public class VaultResponse : Response
        {
            [JsonPropertyName("Items")]
            [JsonRequired]
            public VaultItems Items { get; set; } = new();
        }

        public class VaultItems
        {
            [JsonPropertyName("RevisionsData")]
            [JsonRequired]
            public VaultItem[] Items { get; set; } = [];

            [JsonPropertyName("Total")]
            public int Total { get; set; }

            [JsonPropertyName("LastToken")]
            public string? LastToken { get; set; }
        }

        public class VaultItem
        {
            [JsonPropertyName("ItemID")]
            [JsonRequired]
            public string Id { get; set; } = "";

            [JsonPropertyName("Revision")]
            public int Revision { get; set; }

            [JsonPropertyName("ContentFormatVersion")]
            public int ContentFormatVersion { get; set; }

            [JsonPropertyName("Flags")]
            public int Flags { get; set; }

            [JsonPropertyName("KeyRotation")]
            public int KeyRotation { get; set; }

            [JsonPropertyName("Content")]
            [JsonRequired]
            public string Content { get; set; } = "";

            [JsonPropertyName("ItemKey")]
            [JsonRequired]
            public string ItemKey { get; set; } = "";

            [JsonPropertyName("State")]
            public int State { get; set; }
        }
    }
}
