// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class Client
    {
        public const string ApiUrl = "https://my.1password.com/api/v1";

        public Client(IHttpClient http): this(new JsonHttpClient(http, ApiUrl))
        {
        }

        public Vault[] OpenAllVaults(ClientInfo clientInfo)
        {
            var keychain = new Keychain();

            // Step 1: Request to initiate a new session
            var session = StartNewSession(clientInfo);

            try
            {
                // Step 2: Perform SRP exchange
                var sessionKey = Srp.Perform(clientInfo, session, _http);

                // Step 3: Verify the key with the server
                VerifySessionKey(session, sessionKey);

                // Step 4: Get account info. It contains users, keys, groups, vault info and other stuff.
                //         Not the actual vault data though. That is requested separately.
                var accountInfo = GetAccountInfo(sessionKey);

                // Step 5: Derive and decrypt keys
                DecryptKeys(accountInfo, clientInfo, keychain);

                // Step 6: Get and decrypt vaults
                var vaults = GetVaults(accountInfo, sessionKey, keychain);

                // Done
                return vaults;
            }
            finally
            {
                // Last step: Make sure to sign out in any case
                SignOut(session);
            }
        }

        //
        // Internal
        //

        internal Client(JsonHttpClient http)
        {
            _http = http;
        }

        internal Session StartNewSession(ClientInfo clientInfo)
        {
            var response = GetJson(string.Format("auth/{0}/{1}/-",
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

        internal void VerifySessionKey(Session session, AesKey sessionKey)
        {
            var response = PostEncryptedJson("auth/verify", new {sessionID = session.Id}, sessionKey);

            // Just to verify that it's a valid JSON and it has some keys.
            // Technically it should have failed by now either in decrypt or JSON parse
            response.StringAt("userUuid");
        }

        internal JObject GetAccountInfo(AesKey sessionKey)
        {
            return GetEncryptedJson("accountpanel", sessionKey);
        }

        internal Vault[] GetVaults(JToken accountInfo, AesKey sessionKey, Keychain keychain)
        {
            return accountInfo.At("vaults").Select(i => GetVault(i, sessionKey, keychain)).ToArray();
        }

        internal Vault GetVault(JToken json, AesKey sessionKey, Keychain keychain)
        {
            var id = json.StringAt("uuid");
            var attributes = Decrypt(json.At("encAttrs"), keychain);

            return new Vault(id: id,
                             name: attributes.StringAt("name", ""),
                             description: attributes.StringAt("desc", ""),
                             accounts: GetVaultAccounts(id, sessionKey, keychain));
        }

        internal Account[] GetVaultAccounts(string id, AesKey sessionKey, Keychain keychain)
        {
            var response = GetEncryptedJson(string.Format("vault/{0}/0/items", id), sessionKey);
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

        internal void SignOut(Session session)
        {
            var response = PutJson("session/signout");
            if (response.IntAt("success") != 1)
                throw new InvalidOperationException("Failed to sign out");
        }

        internal static void DecryptKeys(JToken accountInfo, ClientInfo clientInfo, Keychain keychain)
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
            var key = AccountKey.Parse(clientInfo.AccountKey).CombineWith(k2);

            return new AesKey(MasterKeyId, key);
        }

        //
        // HTTP
        //

        internal JObject GetEncryptedJson(string endpoint, AesKey sessionKey)
        {
            return Decrypt(GetJson(endpoint), sessionKey);
        }

        internal JObject PostEncryptedJson(string endpoint, object parameters, AesKey sessionKey)
        {
            var payload = JsonConvert.SerializeObject(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());
            var response = PostJson(endpoint, encryptedPayload.ToDictionary());

            return Decrypt(response, sessionKey);
        }

        internal JObject GetJson(string endpoint)
        {
            // TODO: Set X-AgileBits-* headers
            return _http.Get(endpoint);
        }

        internal JObject PostJson(string endpoint, Dictionary<string, object> parameters)
        {
            // TODO: Set X-AgileBits-* headers
            return _http.Post(endpoint, parameters);
        }

        internal JObject PutJson(string endpoint)
        {
            // TODO: Set X-AgileBits-* headers
            return _http.Put(endpoint);
        }

        internal static JObject Decrypt(JToken response, AesKey sessionKey)
        {
            return JObject.Parse(sessionKey.Decrypt(Encrypted.Parse(response)).ToUtf8());
        }

        internal static JObject Decrypt(JToken response, Keychain keychain)
        {
             return JObject.Parse(keychain.Decrypt(Encrypted.Parse(response)).ToUtf8());
        }



        //
        // Private
        //

        private const string MasterKeyId = "mp";

        private readonly JsonHttpClient _http;
    }
}
