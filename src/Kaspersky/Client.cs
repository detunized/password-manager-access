// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Kaspersky.Response;

namespace PasswordManagerAccess.Kaspersky
{
    // TODO: The protocol is very poorly tested. Write more tests!
    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string accountPassword,
                                          string vaultPassword,
                                          IRestTransport restTransport,
                                          IBoshTransport boshTransport)
        {
            var rest = new RestClient(restTransport);

            // 1. Login
            var (sessionCookie, authCookies) = Login(username, accountPassword, rest);

            try
            {
                // 2. Get XMPP info
                var xmpp = GetXmppInfo(authCookies, rest);

                // 3. The server returns a bunch of alternative URLs with the XMPP BOSH Js library which
                //    are located on different domains. We need to pick one and all the following request
                //    are done using this domain and its sub and sibling domains.
                var jsLibraryHost = ChooseJsLibraryHost(xmpp);

                // 4. Generate JID
                var jid = GenerateJid(xmpp.UserId, jsLibraryHost);

                // 5. Get notify server BOSH url
                var httpsBoshUrl = GetBoshUrl(jid, jsLibraryHost, rest);

                // 6. "find_bosh_bind" call returns a https:// link which doesn't work with the web sockets.
                //    It need to be converted to the wss:// before it could be used.
                var wssBoshUrl = ConvertHttpsBoshUrlToWss(httpsBoshUrl);

                // 6. Connect to the notify XMPP BOSH server
                var bosh = new Bosh(wssBoshUrl, jid, xmpp.XmppCredentials.Password, boshTransport);

                // 7. Get DB info which mainly contains the encryption settings (key derivation info)
                var dbInfoBlob = bosh.GetChanges(GetDatabaseInfoCommand, GetDatabaseInfoCommandId)
                    .Where(x => x.Type == "Database")
                    .Select(x => x.Data)
                    .FirstOrDefault()?
                    .Decode64();

                if (dbInfoBlob == null)
                    throw MakeError("Database info is not found in the response");

                var dbInfo = DatabaseInfo.Parse(dbInfoBlob);

                var version = dbInfo.Version;
                if (!SupportedDbVersions.Contains(version))
                    throw new UnsupportedFeatureException($"Database version {version} is not supported");

                var encryptionKey = Util.DeriveEncryptionKey(vaultPassword, dbInfo);
                var authKey = Util.DeriveMasterPasswordAuthKey(jid.UserId, encryptionKey, dbInfo);

                // 8. Get DB that contains all of the accounts
                // TODO: Test on a huge vault to see if the accounts come in batches and
                //       we need to make multiple requests
                var db = bosh.GetChanges(GetDatabaseCommand, GetDatabaseCommandId, authKey.ToBase64());

                return Parser.ParseVault(db, encryptionKey).ToArray();
            }
            finally
            {
                // 9. Logout
                Logout(sessionCookie, authCookies, rest);
            }
        }

        //
        // Internal
        //

        internal static (string SessionCookie, Dictionary<string, string> AuthCookiess) Login(string username,
                                                                                              string password,
                                                                                              RestClient rest)
        {
            // 1. Request login context token
            var context = RequestLoginContext(rest);

            // 2. Submit the username and the password
            SubmitCredentials(username, password, context, rest);

            // 3. Request user token
            var (token, sessionCookie) = RequestUserTokenAndSessionCookie(context, rest);

            // 4. Finish login
            var authCookies = GetAuthCookies(token, rest);

            return (sessionCookie, authCookies);
        }

        internal static string RequestLoginContext(RestClient rest)
        {
            var response = rest.PostJson<R.Start>(
                "https://hq.uis.kaspersky.com/v3/logon/start",
                new Dictionary<string, object> {["Realm"] = "https://center.kaspersky.com/"});

            if (response.IsSuccessful)
                return response.Data.Context;

            throw MakeError(response);
        }

        internal static void SubmitCredentials(string username, string password, string loginContext, RestClient rest)
        {
            var response = rest.PostJson<R.Result>(
                "https://hq.uis.kaspersky.com/v3/logon/proceed",
                new Dictionary<string, object>
                {
                    ["login"] = username,
                    ["password"] = password,
                    ["logonContext"] = loginContext,
                    ["locale"] = "en",
                    ["captchaType"] = "invisible_recaptcha",
                    ["captchaAnswer"] = "undefined",
                });

            switch (response.Data.Status)
            {
            case "Success":
                if (response.IsSuccessful)
                    return;
                break;

            case "InvalidRegistrationData":
                if (response.IsHttpError)
                    throw new BadCredentialsException("The username or password is incorrect");
                break;
            }

            throw response.IsSuccessful
                ? MakeError($"Unexpected response from {response.RequestUri}")
                : MakeError(response);
        }

        internal static (string Token, string Cookie) RequestUserTokenAndSessionCookie(string loginContext,
                                                                                       RestClient rest)
        {
            var response = rest.PostJson<R.UserToken>(
                "https://hq.uis.kaspersky.com/v3/logon/complete_active",
                new Dictionary<string, object>
                {
                    ["logonContext"] = loginContext,
                    ["TokenType"] = "SamlDeflate",
                    ["RememberMe"] = false,
                });

            if (!response.IsSuccessful)
                throw MakeError(response);

            var cookie = response.Cookies.GetOrDefault(SessionCookieName, "");
            if (cookie.IsNullOrEmpty())
                throw MakeError("Auth session cookie not found");

            return (response.Data.Token, cookie);
        }

        internal static Dictionary<string, string> GetAuthCookies(string userToken, RestClient rest)
        {
            var response = rest.PostJson(
                "https://my.kaspersky.com/SignIn/CompleteRestLogon",
                parameters: new Dictionary<string, object>
                {
                    ["samlDeflatedToken"] = userToken,
                    ["rememberMe"] = false,
                    ["resendActivationLink"] = false,
                },
                headers: new Dictionary<string, string>
                {
                    ["x-requested-with"] = "XMLHttpRequest"
                });

            if (!response.IsSuccessful)
                throw MakeError(response);

            var authCookies = new Dictionary<string, string>(AuthCookieNames.Length);
            foreach (var name in AuthCookieNames)
            {
                var cookie = response.Cookies.GetOrDefault(name, "");
                if (cookie.IsNullOrEmpty())
                    throw MakeError($"Auth cookie '{name}' not found");

                authCookies[name] = cookie;
            }

            return authCookies;
        }

        // TODO: It's not 100% clear that Logout actually succeeds. It needs to be verified
        // against to server to see if it's
        internal static void Logout(string sessionCookie, Dictionary<string, string> authCookies, RestClient rest)
        {
            // We do our best at logging out. It's done a bit messily on the web page.
            // Normally it's done via a bunch of chained redirects controlled by the server.
            // We disable the redirects and make a couple of requests manually. The HTTP
            // errors are ignored deliberately not to fail the whole vault fetching process.

            var response1 = rest.PostForm("https://my.kaspersky.com/SignIn/SignOutTo",
                                          RestClient.NoParameters,
                                          headers: new Dictionary<string, string>()
                                          {
                                              ["Accept"] = "*/*",
                                              ["Host"] = "my.kaspersky.com",
                                          },
                                          cookies: authCookies);
            if (response1.IsNetworkError)
                throw MakeError(response1);

            var response2 = rest.Get("https://hq.uis.kaspersky.com/v3/authenticate?wa=wsignout1.0",
                                     headers: new Dictionary<string, string>()
                                     {
                                         ["Accept"] = "*/*",
                                         ["Host"] = "hq.uis.kaspersky.com",
                                     },
                                     cookies: new Dictionary<string, string>
                                     {
                                         [SessionCookieName] = sessionCookie,
                                     },
                                     maxRedirects: 0);
            if (response2.IsNetworkError)
                throw MakeError(response2);
        }

        internal static R.XmppSettings GetXmppInfo(Dictionary<string, string> authCookies, RestClient rest)
        {
            var response = rest.Get("https://my.kaspersky.com/MyPasswords", cookies: authCookies);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var json = ExtractXmppSettings(response.Content);
            return ParseXmppSettings(json);
        }

        internal static string ExtractXmppSettings(string html)
        {
            const string xmppPrefix = "global.XmppSettings = _.extend(global.XmppSettings || {}, {";
            const string xmppSuffix = "});";

            var prefixIndex = html.IndexOf(xmppPrefix, StringComparison.Ordinal);
            if (prefixIndex < 0)
                throw new InternalErrorException("Failed to parse XMPP settings");

            var xmppStart = prefixIndex + xmppPrefix.Length - 1; // -1 to include the opening curly brace

            var suffixIndex = html.IndexOf(xmppSuffix, xmppStart, StringComparison.Ordinal);
            if (suffixIndex < 0)
                throw new InternalErrorException("Failed to parse XMPP settings");

            return html.Substring(xmppStart, suffixIndex - xmppStart + 1);
        }

        internal static R.XmppSettings ParseXmppSettings(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<R.XmppSettings>(json);
            }
            catch (JsonException e)
            {
                throw MakeError("Failed to parse XMPP settings", e);
            }
        }

        internal static string ChooseJsLibraryHost(R.XmppSettings xmpp)
        {
            if (xmpp.XmppLibraryUrls.Length == 0)
                throw MakeError("The list of XMPP BOSH URLs returned by the server is empty");

            // TODO: We simply pick the first one. Maybe it's better to pick a random one. In the
            //       original Js they cycle through them until they find the one that doesn't fail.
            //       We ignore this bit of extra complexity for now.
            return GetHost(xmpp.XmppLibraryUrls[0]);
        }

        private static Jid GenerateJid(string userId, string jsLibraryHost)
        {
            var index = GetNotifyServerIndex(userId);
            var parentHost = GetParentHost(jsLibraryHost);

            // TODO: JID resource should be random
            return new Jid(userId, $"{index}.{parentHost}", JidResource);
        }

        internal static string GetBoshUrl(Jid jid, string jsLibraryHost, RestClient rest)
        {
            var escapedJid = Uri.EscapeDataString(jid.Full);
            var queryUrl = $"https://{jsLibraryHost}/find_bosh_bind?uid={escapedJid}";

            var response = rest.Get(queryUrl);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var boshUrl = response.Content;
            if (boshUrl.IsNullOrEmpty())
                throw MakeError("Failed to retrieve the XMPP BOSH bind URL");

            return boshUrl;
        }

        internal static string ConvertHttpsBoshUrlToWss(string httpsUrl)
        {
            var host = GetHost(httpsUrl);
            return $"wss://{host}/ws";
        }

        internal static string GetHost(string url)
        {
            return new Uri(url).Host;
        }

        internal static int GetNotifyServerIndex(string username)
        {
            return (int)(Crypto.Crc32(username.ToBytes()) % 100);
        }

        internal static string GetParentHost(string host)
        {
            var dot = host.IndexOf('.');
            if (dot < 0)
                throw MakeError($"Expected '{host}' to have a subdomain");

            return host.Substring(dot + 1);
        }

        internal static BaseException MakeError(RestResponse<string> response)
        {
            if (response.IsNetworkError)
                return MakeError("Network error has occurred", response.Error);

            // TODO: Support server reported error. One real example:
            // {"ErrorDescription":"Too many requests.","TraceId":"509a0be4-6cca-4e0b-8571-63795d3ef826"}

            // TODO: Make this more descriptive
            return MakeError($"Request to '{response.RequestUri}' failed");
        }

        internal static BaseException MakeError(string message, Exception inner = null)
        {
            return new InternalErrorException(message, inner);
        }

        //
        // Data
        //

        internal const string SessionCookieName = "AuthSession";
        internal static readonly string[] AuthCookieNames = {"MyKFedAuth", "myk_sid", "myk_auth"};

        internal const string DeviceKind = "browser";
        internal const int ServiceId = 5;
        internal const string JidResource = "portalsorucr8yj2l"; // TODO: Make this random

        // BOSH commands
        internal const string GetDatabaseInfoCommand = "kpmgetdatabasecommand";
        internal const string GetDatabaseInfoCommandId = "1830647823";
        internal const string GetDatabaseCommand = "kpmgetserverchangecommand";
        internal const string GetDatabaseCommandId = "660529337";

        internal static readonly int[] SupportedDbVersions = {Parser.Version8, Parser.Version9};
    }
}
