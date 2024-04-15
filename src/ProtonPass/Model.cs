// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Text.Json.Serialization;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Model
    {
        public class Error
        {
            [JsonPropertyName("Code")]
            [JsonRequired]
            public int Code { get; set; }

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

        public class Session
        {
            [JsonPropertyName("Code")]
            [JsonRequired]
            public int Code { get; set; }

            [JsonPropertyName("AccessToken")]
            [JsonRequired]
            public string AccessToken { get; set; }

            [JsonPropertyName("RefreshToken")]
            [JsonRequired]
            public string RefreshToken { get; set; }

            [JsonPropertyName("TokenType")]
            [JsonRequired]
            public string TokenType { get; set; }

            [JsonPropertyName("Scopes")]
            public object[]? Scopes { get; set; }

            [JsonPropertyName("UID")]
            [JsonRequired]
            public string Id { get; set; }

            [JsonPropertyName("LocalID")]
            public int LocalId { get; set; }
        }

        internal class AuthInfo
        {
            [JsonPropertyName("Code")]
            [JsonRequired]
            public int Code { get; set; }

            [JsonPropertyName("Modulus")]
            [JsonRequired]
            public string Modulus { get; set; }

            [JsonPropertyName("ServerEphemeral")]
            [JsonRequired]
            public string ServerEphemeral { get; set; }

            [JsonPropertyName("Version")]
            public int Version { get; set; }

            [JsonPropertyName("Salt")]
            [JsonRequired]
            public string Salt { get; set; }

            [JsonPropertyName("SRPSession")]
            [JsonRequired]
            public string SrpSession { get; set; }

            [JsonPropertyName("Username")]
            public string Username { get; set; }
        }
    }
}
