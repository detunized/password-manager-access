// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.LastPass;

internal static partial class Client
{
    public static async Task<bool> IsSsoAccount(string username, IRestTransport transport, CancellationToken cancellationToken)
    {
        var rest = new RestClient(transport, "https://lastpass.com", useSystemJson: true);
        var loginInfo = await GetLoginInfo(username, rest, cancellationToken).ConfigureAwait(false);
        return loginInfo.LoginType != Model.LoginType.Regular;
    }

    //
    // Internal
    //

    internal static async Task<Model.SsoLoginInfo> GetLoginInfo(string username, RestClient rest, CancellationToken cancellationToken)
    {
        var ssoLoginInfo = await rest.GetAsync<Model.SsoLoginInfo>("lmiapi/login/type?username=" + username.EncodeUri(), cancellationToken)
            .ConfigureAwait(false);

        if (ssoLoginInfo.IsSuccessful)
            return ssoLoginInfo.Data;

        throw MakeError(ssoLoginInfo);
    }

    internal static async Task<(string Password, Dictionary<string, object> ExtraParameters)> PerformSsoLogin(
        string username,
        Model.SsoLoginInfo ssoInfo,
        ClientInfo clientInfo,
        IAsyncUi ui,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // We don't support all the SSO methods yet
        switch (ssoInfo.LoginType)
        {
            case Model.LoginType.OpenIdConnect:
                break;
            default:
                throw new UnsupportedFeatureException($"Unsupported SSO method: {ssoInfo.LoginType}");
        }

        // We don't support all the SSO providers yet
        switch (ssoInfo.OpenIdConnectProvider)
        {
            case Model.OpenIdConnectProvider.Azure:
                break;
            default:
                throw new UnsupportedFeatureException($"Unsupported SSO provider: {ssoInfo.OpenIdConnectProvider}");
        }

        if (ssoInfo.OpenIdConnectAuthority.IsNullOrEmpty())
            throw new InternalErrorException("Expected a valid authority");

        // We need a special rest client that is not tied to LastPass
        var noBaseRest = new RestClient(rest.Transport, useSystemJson: true);

        // 1. Get the OIDC configuration
        var oidcConfig = await GetAndValidateOpenIdConnectConfig(ssoInfo.OpenIdConnectAuthority, noBaseRest, cancellationToken).ConfigureAwait(false);

        // 2. Generate a challenge
        var challenge = GenerateSsoChallenge();

        // 3. Build the SSO URL for the user to login with
        var ssoUrl = BuildSsoUrl(username, ssoInfo, oidcConfig, challenge);

        // 4. Let the user login to the SSO provider
        var ssoResult = await ui.PerformSsoLogin(ssoUrl, RedirectUrl, cancellationToken).ConfigureAwait(false);

        // 5. It's either a success or a cancelation
        var redirectedToUrl = ssoResult.Match(
            redirectedTo => redirectedTo,
            canceled => throw new CanceledSsoLoginException("SSO login canceled by the user")
        );

        // 6. Parse the redirect URL to get the code
        var code = ExtractAndValidateCodeFromRedirectUrl(redirectedToUrl, challenge);

        // TODO: Everything below in only valid for Azure. For other providers we need to add the code and test it.

        // 7. Exchange the code for a session
        var token = await ExchangeCodeForToken(code, challenge, ssoInfo, oidcConfig, noBaseRest, cancellationToken).ConfigureAwait(false);

        // 8. Get the SSO user info
        var userInfo = await RequestSsoUserInfo(token, oidcConfig, noBaseRest, cancellationToken).ConfigureAwait(false);

        // 9. Match the usernames
        if (!AreUsernamesValid(username, userInfo, token.IdToken))
            throw new InternalErrorException("Expected username in the JWT token and the SSO info to match the provided username");

        // 10. Get K1 from Azure
        // TODO: Other providers implement it differently
        var k1 = await RequestK1FromAzure(token, oidcConfig, noBaseRest, cancellationToken).ConfigureAwait(false);

        // 11. Get K2 from ALP server
        var k2 = await RequestK2FromAlp(ssoInfo, token, noBaseRest, cancellationToken).ConfigureAwait(false);

        // 12. Calculate the password and fragment ID
        var (password, fragmentId) = CalculateSsoPasswordAndFragmentId(k1, k2.K2);

        return (
            password,
            new Dictionary<string, object>
            {
                ["xml"] = "1", // TODO: Do we need to override this?
                ["method"] = "web", // TODO: Do we need to override this?
                ["authsessionid"] = "",
                ["alpfragmentid"] = k2.FragmentId,
                ["calculatedfragmentid"] = fragmentId,
            }
        );
    }

    internal static async Task<Model.OpenIdConnectConfig> GetAndValidateOpenIdConnectConfig(
        string authority,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.GetAsync<Model.OpenIdConnectConfig>(authority, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessful)
            throw MakeError(response);

        var config = response.Data;

        if (config.AuthorizationEndpoint.IsNullOrEmpty())
            throw new InternalErrorException("Expected a valid authorization endpoint");

        if (config.TokenEndpoint.IsNullOrEmpty())
            throw new InternalErrorException("Expected a valid token endpoint");

        return config;
    }

    internal readonly record struct SsoChallenge(string State, string CodeVerifier, string CodeChallenge, string Nonce);

    internal static SsoChallenge GenerateSsoChallenge()
    {
        var codeVerifier = Crypto.RandomHex(96);
        return new SsoChallenge(Crypto.RandomHex(32), codeVerifier, Crypto.Sha256(codeVerifier).ToUrlSafeBase64NoPadding(), Crypto.RandomHex(16));
    }

    internal static string BuildSsoUrl(string username, Model.SsoLoginInfo ssoInfo, Model.OpenIdConnectConfig oidcConfig, SsoChallenge challenge)
    {
        // TODO: It seems like PKCE is required. Is there a way to turn it off for testing?
        var responseType = ssoInfo.IsPkceEnabled ? "code" : "id_token token";
        var responseMode = ssoInfo.IsPkceEnabled ? "fragment" : null;

        var urlParams = new Dictionary<string, string>
        {
            ["client_id"] = ssoInfo.OpenIdConnectClientId,
            ["redirect_uri"] = RedirectUrl,
            ["response_type"] = responseType,
            ["scope"] = GetScopes(ssoInfo),
            ["state"] = challenge.State,
            ["code_challenge"] = challenge.CodeChallenge,
            ["code_challenge_method"] = "S256",
            ["response_mode"] = responseMode,
            ["login_hint"] = username,
            ["nonce"] = challenge.Nonce,
        };

        return oidcConfig.AuthorizationEndpoint + "?" + string.Join("&", urlParams.Select(kv => kv.Key + "=" + kv.Value.EncodeUri()));
    }

    internal static string GetScopes(Model.SsoLoginInfo ssoInfo)
    {
        return ssoInfo.OpenIdConnectProvider switch
        {
            Model.OpenIdConnectProvider.Azure => "openid email profile user.readwrite",
            Model.OpenIdConnectProvider.OktaWithoutAuthorizationServer => "openid email profile groups",
            Model.OpenIdConnectProvider.Google =>
                "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/drive.install https://www.googleapis.com/auth/drive.file",
            Model.OpenIdConnectProvider.PingOne => "openid email profile lastpass",
            _ => "openid email profile",
        };
    }

    internal static string ExtractAndValidateCodeFromRedirectUrl(string redirectedToUrl, SsoChallenge challenge)
    {
        if (redirectedToUrl == null || !redirectedToUrl.StartsWith(RedirectUrl))
            throw new InternalErrorException($"Expected a valid redirect URL, got '{redirectedToUrl}'");

        var code = Url.ExtractQueryParameter(redirectedToUrl, "code");
        if (code.IsNullOrEmpty())
            throw new InternalErrorException("Expected a valid code in the redirect URL");

        var state = Url.ExtractQueryParameter(redirectedToUrl, "state");
        if (state != challenge.State)
            throw new InternalErrorException("State mismatch");

        return code;
    }

    internal static async Task<Model.TokenInfo> ExchangeCodeForToken(
        string code,
        SsoChallenge challenge,
        Model.SsoLoginInfo ssoInfo,
        Model.OpenIdConnectConfig oidcConfig,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostFormAsync<Model.TokenInfo>(
                oidcConfig.TokenEndpoint,
                new Dictionary<string, object>
                {
                    ["client_id"] = ssoInfo.OpenIdConnectClientId,
                    ["code"] = code,
                    ["redirect_uri"] = RedirectUrl,
                    ["code_verifier"] = challenge.CodeVerifier,
                    ["grant_type"] = "authorization_code",
                },
                headers: new Dictionary<string, string> { ["Origin"] = ChromeExtension },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        var token = response.Data;
        if (token.Scope?.Split(' ').Contains("openid") != true)
            throw new InternalErrorException($"Expected 'openid' scope, got '{token.Scope}'");

        return token;
    }

    internal static async Task<Model.UserInfo> RequestSsoUserInfo(
        Model.TokenInfo token,
        Model.OpenIdConnectConfig oidcConfig,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.GetAsync<Model.UserInfo>(
                oidcConfig.UserInfoEndpoint,
                headers: new Dictionary<string, string> { ["Authorization"] = $"Bearer {token.AccessToken}" },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (response.IsSuccessful)
            return response.Data;

        throw MakeError(response);
    }

    internal static bool AreUsernamesValid(string username, Model.UserInfo userInfo, string idToken)
    {
        if (username != userInfo.Email.ToLowerInvariant())
            return false;

        // Poor man's JWT parse
        var payload = idToken.Split('.')[1].Decode64Loose();
        var payloadJson = JsonSerializer.Deserialize<Model.TokenPayload>(payload);

        if (username != payloadJson.PreferredUsername.ToLowerInvariant())
            return false;

        return true;
    }

    internal static async Task<string> RequestK1FromAzure(
        Model.TokenInfo token,
        Model.OpenIdConnectConfig oidcConfig,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.GetAsync<Model.AzureK1>(
                $"https://{oidcConfig.MsGraphHost}/v1.0/me?$select=id,displayName,mail&$expand=extensions",
                headers: new Dictionary<string, string> { ["Authorization"] = $"Bearer {token.AccessToken}" },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        var k1 = response.Data.Extensions.FirstOrDefault(x => x.Id == "com.lastpass.keys")?.LastPassK1;
        if (k1.IsNullOrEmpty())
            throw new InternalErrorException("Expected a valid K1");

        return k1;
    }

    internal static async Task<Model.AlpK2> RequestK2FromAlp(
        Model.SsoLoginInfo ssoInfo,
        Model.TokenInfo token,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostJsonAsync<Model.AlpK2>(
                "https://accounts.lastpass.com/federatedlogin/api/v1/getkey",
                new Dictionary<string, object> { ["company_id"] = ssoInfo.CompanyId, ["id_token"] = token.IdToken },
                headers: new Dictionary<string, string>
                {
                    ["Origin"] = ChromeExtension,
                    // ["User-Agent"] =
                    //     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (response.IsSuccessful)
            return response.Data;

        throw MakeError(response);
    }

    internal static (string Password, string FragmentId) CalculateSsoPasswordAndFragmentId(string k1, string k2) =>
        CalculateSsoPasswordAndFragmentId(k1.Decode64Loose(), k2.Decode64Loose());

    internal static (string Password, string FragmentId) CalculateSsoPasswordAndFragmentId(byte[] k1, byte[] k2)
    {
        if (k1.Length != k2.Length)
            throw new InternalErrorException("Expected K1 and K2 to have the same length");

        var k1XorK2 = new byte[k1.Length];
        for (int i = 0; i < k1.Length; i++)
            k1XorK2[i] = (byte)(k1[i] ^ k2[i]);

        var k1Sha256 = Crypto.Sha256(k1);
        var k1XorK2Sha256 = Crypto.Sha256(k1XorK2);

        return (k1XorK2Sha256.ToBase64(), k1Sha256.ToBase64());
    }

    //
    // Data
    //

    internal const string ChromeExtension = "chrome-extension://hdokiejnpimakedhajhdlcegeplioahd";
    internal const string RedirectUrl = "https://accounts.lastpass.com/federated/oidcredirect.html";
}
