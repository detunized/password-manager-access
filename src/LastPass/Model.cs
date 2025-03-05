// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Text.Json.Serialization;
using Newtonsoft.Json;

namespace PasswordManagerAccess.LastPass
{
    internal static class Model
    {
        // TODO: Convert to System.Text.Json
        public class DuoStatus
        {
            [JsonProperty("status")]
            public string Status { get; set; } = "";

            [JsonProperty("oneTimeToken")]
            public string OneTimeToken { get; set; } = "";
        }

        public enum LoginType
        {
            Regular = 0,
            Saml1 = 1, // TODO: It's not clear what this mode is exactly
            Saml2 = 2, // TODO: It's not clear what this mode is exactly
            OpenIdConnect = 3,
        }

        public enum OpenIdConnectProvider
        {
            Azure = 0,
            Okta = 1,
            OktaWithoutAuthorizationServer = 2,
            Google = 3,
            PingOne = 4,
            OneLogin = 5,
        }

        public class SsoLoginInfo
        {
            [JsonPropertyName("type")]
            public LoginType LoginType { get; set; }

            [JsonPropertyName("Provider")]
            public OpenIdConnectProvider OpenIdConnectProvider { get; set; }

            [JsonPropertyName("OpenIDConnectAuthority")]
            public string OpenIdConnectAuthority { get; set; }

            [JsonPropertyName("OpenIDConnectClientId")]
            public string OpenIdConnectClientId { get; set; }

            [JsonPropertyName("CompanyId")]
            public int CompanyId { get; set; }

            [JsonPropertyName("PkceEnabled")]
            public bool IsPkceEnabled { get; set; }

            [JsonPropertyName("OldEmail")]
            public string OldEmail { get; set; }
        }

        public class OpenIdConnectConfig
        {
            [JsonPropertyName("authorization_endpoint")]
            public string AuthorizationEndpoint { get; set; }

            [JsonPropertyName("token_endpoint")]
            public string TokenEndpoint { get; set; }

            [JsonPropertyName("userinfo_endpoint")]
            public string UserInfoEndpoint { get; set; }

            [JsonPropertyName("msgraph_host")]
            public string MsGraphHost { get; set; }
        }

        public class TokenInfo
        {
            [JsonPropertyName("token_type")]
            public string TokenType { get; set; }

            [JsonPropertyName("scope")]
            public string Scope { get; set; }

            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; }

            [JsonPropertyName("id_token")]
            public string IdToken { get; set; }
        }

        public class TokenPayload
        {
            [JsonPropertyName("email")]
            public string Email { get; set; }

            [JsonPropertyName("preferred_username")]
            public string PreferredUsername { get; set; }
        }

        public class UserInfo
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }

            [JsonPropertyName("email")]
            public string Email { get; set; }
        }

        public class AzureK1
        {
            [JsonPropertyName("@odata.context")]
            public string OdataContext { get; set; }

            [JsonPropertyName("id")]
            public string Id { get; set; }

            [JsonPropertyName("extensions")]
            public Extension[] Extensions { get; set; }

            public class Extension
            {
                [JsonPropertyName("@odata.type")]
                public string OdataType { get; set; }

                [JsonPropertyName("id")]
                public string Id { get; set; }

                [JsonPropertyName("LastPassK1")]
                public string LastPassK1 { get; set; }
            }
        }

        public class AlpK2
        {
            [JsonPropertyName("k2")]
            public string K2 { get; set; }

            [JsonPropertyName("fragment_id")]
            public string FragmentId { get; set; }
        }
    }
}
