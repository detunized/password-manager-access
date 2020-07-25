// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Kaspersky.Response;

namespace PasswordManagerAccess.Kaspersky
{
    internal static class Client
    {
        public static void OpenVault(string username, string password, IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // 1. Request login context token
            var loginContext = RequestLoginContext(rest);

            // 2. Login
            Login(username, password, loginContext, rest);

            // 3. Request user token
            var token = RequestUserToken(loginContext, rest);

            // 4. Finish login
            var authCookie = GetAuthCookie(token, rest);

            // 5. Get XMPP info
            var xmpp = GetXmppInfo(authCookie, rest);

            // 6. The server returns a bunch of alternative URLs with the XMPP BOSH Js library which
            //    are located on different domains. We need to pick one and all the following request
            //    are done using this domain and its sub and sibling domains.
            var jsLibraryHost = ChooseJsLibraryHost(xmpp);

            // 7. Generate JID
            var jid = GenerateJid(xmpp.UserId, jsLibraryHost);

            // 8. Get notify server BOSH url
            var boshUrl = GetBoshUrl(jid, jsLibraryHost, rest);

            // 9. Connect to the notify XMPP BOSH server
            var bosh = new Bosh(boshUrl);
            bosh.Connect(jid, xmpp.XmppCredentials.Password, transport);

            // 10. Get DB info which mainly contains the encryption settings (key derivation info)
            var dbInfoBlob = bosh.GetChanges(GetDatabaseInfoCommand, GetDatabaseInfoCommandId)
                .Where(x => x.Type == "Database")
                .Select(x => x.Data)
                .FirstOrDefault()?
                .Decode64();

            if (dbInfoBlob == null)
                throw MakeError("Database info is not found in the response");

            var dbInfo = DatabaseInfo.Parse(dbInfoBlob);

            var version = dbInfo.Version;
            if (version != 2)
                throw new UnsupportedFeatureException($"Database version {version} is not supported");

            var authKey = Util.DeriveMasterPasswordAuthKey(jid.UserId, password, dbInfo);

            // 11. Get DB that contains all of the accounts
            // TODO: Test on a huge vault to see if the accounts come in batches and we need to make multiple requests
            var db = bosh.GetChanges(GetDatabaseCommand, GetDatabaseCommandId, authKey.ToBase64());

            // TODO: Parse the db here
        }

        //
        // Internal
        //

        internal static string RequestLoginContext(RestClient rest)
        {
            var response = rest.PostJson<R.Start>(
                "https://hq.uis.kaspersky.com/v3/logon/start",
                new Dictionary<string, object> {["Realm"] = "https://center.kaspersky.com/"});

            if (response.IsSuccessful)
                return response.Data.Context;

            throw MakeError(response);
        }

        // TODO: Handle and test invalid username and password
        internal static void Login(string username, string password, string loginContext, RestClient rest)
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

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Status == "Success")
                return;

            throw new InternalErrorException($"Unexpected response from {response.RequestUri}");
        }

        internal static string RequestUserToken(string loginContext, RestClient rest)
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

            return response.Data.Token;
        }

        internal static string GetAuthCookie(string userToken, RestClient rest)
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

            var cookie = response.Cookies.GetOrDefault(AuthCookieName, "");
            if (cookie.IsNullOrEmpty())
                throw MakeError("Auth cookie not found");

            return cookie;
        }

        internal static R.XmppSettings GetXmppInfo(string authCookie, RestClient rest)
        {
            var response = rest.Get("https://my.kaspersky.com/MyPasswords",
                                    cookies: new Dictionary<string, string> {[AuthCookieName] = authCookie});
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

        internal static object DecryptItem(Bosh.Change item)
        {
            var blob = item.Data.Decode64();
            if (blob.Length < 4)
                throw MakeError("Database is corrupted: encrypted item is too short");

            var version = blob[0];
            if (version == Version92)
                return DecryptItemVersion92(blob);

            throw new UnsupportedFeatureException($"Database item version {version} is not supported");
        }

        internal static object DecryptItemVersion92(byte[] blob)
        {
            using var inputStream = new MemoryStream(blob, false);

            // Skip version (4 bytes) and Zlib header (2 bytes)
            for (var i = 0; i < 6; i++)
                inputStream.ReadByte();

            using var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress);
            var decompressed = deflateStream.ReadAll();

            var json = JObject.Parse(decompressed.ToUtf8());

            var fields = json["fields"];
            var fieldProperties = json["attributes"]["propertiesMetadata"];

            // Field types:
            //
            // 0: "Text"
            // 1: "Number"
            // 2: "Boolean"
            // 3: "Blob"
            // 4: "Real"
            // 5: "Json"
            //
            // Text: 0
            // Number: 1
            // Boolean: 2
            // Blob: 3
            // Real: 4
            // Json: 5

            // Fields could be encrypted or not, this is defined by the field attributes.
            // The stored type of the field is ignored by the parser and it uses a hardcoded
            // table of known names and associated types.

            // Encrypted blob has a header of 12 words (48 bytes)
            // 16 bytes of IV
            // 32 bytes of HMAC
            // The rest of the blob contains the ciphertext encrypted with AES-256-CBC with PKCS#7 padding.

            // For version 9.2 strings are stored in UTF-16. Otherwise it's UTF-8.

            // Look for `function E(e, t, n) {` for more info.

            // HMAC for versions 9+ are calculated on the encrypted data
            // HMAC for version 8 is calculated on the decrypted string

            return null;
        }

        internal static BaseException MakeError(RestResponse<string> response)
        {
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

        internal const string AuthCookieName = "MyKFedAuth";
        internal const string DeviceKind = "browser";
        internal const int ServiceId = 5;
        internal const string JidResource = "portalsorucr8yj2l"; // TODO: Make this random

        internal const int Version8 = 1;
        internal const int Version9 = 2;
        internal const int Version92 = 3;

        // BOSH commands
        internal const string GetDatabaseInfoCommand = "kpmgetdatabasecommand";
        internal const string GetDatabaseInfoCommandId = "1830647823";
        internal const string GetDatabaseCommand = "kpmgetserverchangecommand";
        internal const string GetDatabaseCommandId = "660529337";
    }
}
