// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    public static class Client
    {
        public const string ApiUrl = "https://my.1password.com/api/v1";
        public const string ClientName = "1Password for Web";
        public const string ClientVersion = "348";
        public const string ClientId = ClientName + "/" + ClientVersion;

        // Public entry point to the library.
        // We try to mimic the remote structure, that's why there's an array of vaults.
        // We open all the ones we can.
        public static Vault[] OpenAllVaults(string username,
                                            string password,
                                            string accountKey,
                                            string uuid)
        {
            return OpenAllVaults(username, password, accountKey, uuid, new HttpClient());
        }

        public static Vault[] OpenAllVaults(string username,
                                            string password,
                                            string accountKey,
                                            string uuid,
                                            IHttpClient http)
        {
            return OpenAllVaults(new ClientInfo(username, password, accountKey, uuid), http);
        }

        //
        // Internal
        //

        internal static Vault[] OpenAllVaults(ClientInfo clientInfo, IHttpClient http)
        {
            var keychain = new Keychain();
            var jsonHttp = MakeJsonClient(http);

            // Step 1: Request to initiate a new session
            var session = StartNewSession(clientInfo, jsonHttp);

            // After a new session has been initiated, all the subsequent requests must be
            // signed with the session ID.
            jsonHttp.Headers["X-AgileBits-Session-ID"] = session.Id;

            try
            {
                // Step 2: Perform SRP exchange
                var sessionKey = Srp.Perform(clientInfo, session, jsonHttp);

                // Step 3: Verify the key with the server
                VerifySessionKey(session, sessionKey, jsonHttp);

                // Step 4: Get account info. It contains users, keys, groups, vault info and other stuff.
                //         Not the actual vault data though. That is requested separately.
                var accountInfo = GetAccountInfo(sessionKey, jsonHttp);

                // Step 5: Derive and decrypt keys
                DecryptKeys(accountInfo, clientInfo, keychain);

                // Step 6: Get and decrypt vaults
                var vaults = GetVaults(accountInfo, sessionKey, keychain, jsonHttp);

                // Done
                return vaults;
            }
            finally
            {
                // Last step: Make sure to sign out in any case
                SignOut(jsonHttp);
            }
        }

        internal static JsonHttpClient MakeJsonClient(IHttpClient http)
        {
            var json = new JsonHttpClient(http, ApiUrl);
            json.Headers["X-AgileBits-Client"] = ClientId;

            return json;
        }

        internal static Session StartNewSession(ClientInfo clientInfo, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Get(string.Format("auth/{0}/{1}/-",
                                                      clientInfo.Username,
                                                      clientInfo.Uuid));
            var status = response.StringAt("status");
            switch (status)
            {
            case "ok":
                return Session.Parse(response);
            default:
                // TODO: Use custom exception
                throw new InvalidOperationException(
                    string.Format(
                        "Failed to start a new session, unsupported response status '{0}'",
                        status));
            }
        }

        internal static void VerifySessionKey(Session session,
                                              AesKey sessionKey,
                                              JsonHttpClient jsonHttp)
        {
            var response = PostEncryptedJson("auth/verify",
                                             new {sessionID = session.Id},
                                             sessionKey,
                                             jsonHttp);

            // Just to verify that it's a valid JSON and it has some keys.
            // Technically it should have failed by now either in decrypt or JSON parse
            response.StringAt("userUuid");
        }

        internal static JObject GetAccountInfo(AesKey sessionKey, JsonHttpClient jsonHttp)
        {
            return GetEncryptedJson("accountpanel", sessionKey, jsonHttp);
        }

        internal static Vault[] GetVaults(JToken accountInfo,
                                          AesKey sessionKey,
                                          Keychain keychain,
                                          JsonHttpClient jsonHttp)
        {
            return accountInfo.At("vaults")
                .Select(i => GetVault(i, sessionKey, keychain, jsonHttp))
                .ToArray();
        }

        internal static Vault GetVault(JToken json,
                                       AesKey sessionKey,
                                       Keychain keychain,
                                       JsonHttpClient jsonHttp)
        {
            var id = json.StringAt("uuid");
            var attributes = Decrypt(json.At("encAttrs"), keychain);

            return new Vault(id: id,
                             name: attributes.StringAt("name", ""),
                             description: attributes.StringAt("desc", ""),
                             accounts: GetVaultAccounts(id, sessionKey, keychain, jsonHttp));
        }

        internal static Account[] GetVaultAccounts(string id,
                                                   AesKey sessionKey,
                                                   Keychain keychain,
                                                   JsonHttpClient jsonHttp)
        {
            var response = GetEncryptedJson(string.Format("vault/{0}/0/items", id),
                                            sessionKey,
                                            jsonHttp);
            return response.At("items").Select(i => ParseAccount(i, keychain)).ToArray();
        }

        internal static Account ParseAccount(JToken json, Keychain keychain)
        {
            var overview = Decrypt(json.At("encOverview"), keychain);
            var details = Decrypt(json.At("encDetails"), keychain);
            var fields = details.At("fields");

            return new Account(json.StringAt("uuid", ""),
                               overview.StringAt("title", ""),
                               FindAccountField(fields, "username"),
                               FindAccountField(fields, "password"),
                               overview.StringAt("url", ""),
                               details.StringAt("notesPlain", ""));
        }

        internal static string FindAccountField(JToken json, string name)
        {
            foreach (var i in json)
                if (i.StringAt("designation", "") == name)
                    return i.StringAt("value", "");

            return "";
        }

        internal static void SignOut(JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Put("session/signout");
            if (response.IntAt("success") != 1)
                throw new InvalidOperationException("Failed to sign out");
        }

        internal static void DecryptKeys(JToken accountInfo,
                                         ClientInfo clientInfo,
                                         Keychain keychain)
        {
            DecryptKeysets(accountInfo.At("user/keysets"), clientInfo, keychain);
            DecryptGroupKeys(accountInfo.At("groups"), keychain);
            DecryptVaultKeys(accountInfo.At("user/vaultAccess"), keychain);
        }

        internal static void DecryptKeysets(JToken keysets, ClientInfo clientInfo, Keychain keychain)
        {
            var sorted = keysets.OrderBy(i => i.IntAt("sn")).Reverse().ToArray();
            if (sorted[0].StringAt("encryptedBy") != MasterKeyId)
                throw new InvalidOperationException(
                    string.Format("Invalid keyset (key must be encrypted by '{0}')", MasterKeyId));

            var keyInfo = sorted[0].At("encSymKey");
            var masterKey = DeriveMasterKey(algorithm: keyInfo.StringAt("alg"),
                                            iterations: keyInfo.IntAt("p2c"),
                                            salt: keyInfo.StringAt("p2s").Decode64(),
                                            clientInfo: clientInfo);
            keychain.Add(masterKey);

            foreach (var i in sorted)
                DecryptKeyset(i, keychain);
        }

        internal static void DecryptGroupKeys(JToken groups, Keychain keychain)
        {
            foreach (var i in groups)
                DecryptKeyset(i.At("userMembership/keyset"), keychain);
        }

        internal static void DecryptVaultKeys(JToken vaults, Keychain keychain)
        {
            foreach (var i in vaults)
                DecryptAesKey(i.At("encVaultKey"), keychain);
        }

        internal static void DecryptKeyset(JToken keyset, Keychain keychain)
        {
            DecryptAesKey(keyset.At("encSymKey"), keychain);
            DecryptRsaKey(keyset.At("encPriKey"), keychain);
        }

        internal static void DecryptAesKey(JToken key, Keychain keychain)
        {
            keychain.Add(AesKey.Parse(Decrypt(key, keychain)));
        }

        internal static void DecryptRsaKey(JToken key, Keychain keychain)
        {
            keychain.Add(RsaKey.Parse(Decrypt(key, keychain)));
        }

        internal static AesKey DeriveMasterKey(string algorithm,
                                               int iterations,
                                               byte[] salt,
                                               ClientInfo clientInfo)
        {
            if (!algorithm.StartsWith("PBES2g-"))
                throw new InvalidOperationException(
                    string.Format("Key derivation algorithm '{0}' is not supported", algorithm));

            // TODO: Check if the Unicode normalization is the correct one.

            var k1 = Crypto.Hkdf(algorithm, salt, clientInfo.Username.ToLower().ToBytes());
            var k2 = Crypto.Pbes2(algorithm, clientInfo.Password.Normalize(), k1, iterations);
            var key = clientInfo.AccountKey.CombineWith(k2);

            return new AesKey(MasterKeyId, key);
        }

        //
        // HTTP
        //

        internal static JObject GetEncryptedJson(string endpoint,
                                                 AesKey sessionKey,
                                                 JsonHttpClient jsonHttp)
        {
            return Decrypt(jsonHttp.Get(endpoint), sessionKey);
        }

        internal static JObject PostEncryptedJson(string endpoint,
                                                  object parameters,
                                                  AesKey sessionKey,
                                                  JsonHttpClient jsonHttp)
        {
            var payload = JsonConvert.SerializeObject(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());
            var response = jsonHttp.Post(endpoint, encryptedPayload.ToDictionary());

            return Decrypt(response, sessionKey);
        }

        internal static JObject Decrypt(JToken json, AesKey sessionKey)
        {
            return JObject.Parse(sessionKey.Decrypt(Encrypted.Parse(json)).ToUtf8());
        }

        internal static JObject Decrypt(JToken json, Keychain keychain)
        {
            return JObject.Parse(keychain.Decrypt(Encrypted.Parse(json)).ToUtf8());
        }

        //
        // Private
        //

        private const string MasterKeyId = "mp";
    }
}
