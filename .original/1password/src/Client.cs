// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    public static class Client
    {
        public const string DefaultDomain = "my.1password.com";
        public const string ClientName = "1Password Extension";
        public const string ClientVersion = "10703"; // TODO: This needs to be updated every now and then.
        public const string ClientId = ClientName + "/" + ClientVersion;

        public enum Region
        {
            Global,
            Europe,
            Canada
        }

        // Public entry point to the library.
        // We try to mimic the remote structure, that's why there's an array of vaults.
        // We open all the ones we can.
        // Valid domains are: my.1password.com, my.1password.eu, my.1password.ca
        public static Vault[] OpenAllVaults(string username,
                                            string password,
                                            string accountKey,
                                            string uuid,
                                            string domain = DefaultDomain)
        {
            return OpenAllVaults(username, password, accountKey, uuid, domain, new HttpClient());
        }

        // Alternative entry point with a predefined region
        public static Vault[] OpenAllVaults(string username,
                                            string password,
                                            string accountKey,
                                            string uuid,
                                            Region region)
        {
            return OpenAllVaults(username,
                                 password,
                                 accountKey,
                                 uuid,
                                 GetDomain(region),
                                 new HttpClient());
        }

        public static Vault[] OpenAllVaults(string username,
                                            string password,
                                            string accountKey,
                                            string uuid,
                                            string domain,
                                            IHttpClient http)
        {
            return OpenAllVaults(new ClientInfo(username, password, accountKey, uuid, domain), http);
        }

        // Use this function to generate a unique random identifier for each new client.
        public static string GenerateRandomUuid()
        {
            return Crypto.RandomUuid();
        }

        public static string GetDomain(Region region)
        {
            switch (region)
            {
            case Region.Global:
                return "my.1password.com";
            case Region.Europe:
                return "my.1password.eu";
            case Region.Canada:
                return "my.1password.ca";
            }

            throw new ArgumentException("Region values is invalid");
        }

        //
        // Internal
        //

        internal static Vault[] OpenAllVaults(ClientInfo clientInfo, IHttpClient http)
        {
            var keychain = new Keychain();
            var jsonHttp = MakeJsonClient(http, GetApiUrl(clientInfo.Domain));

            // Step 1: Request to initiate a new session
            var session = StartNewSession(clientInfo, jsonHttp);

            // After a new session has been initiated, all the subsequent requests must be
            // signed with the session ID.
            jsonHttp = MakeJsonClient(jsonHttp, session.Id);

            // Step 2: Perform SRP exchange
            var sessionKey = Srp.Perform(clientInfo, session, jsonHttp);

            // Assign a request signer now that we have a key.
            // All the following requests are expected to be signed with the MAC.
            jsonHttp.Signer = new MacRequestSigner(session, sessionKey);

            // Step 3: Verify the key with the server
            VerifySessionKey(clientInfo, session, sessionKey, jsonHttp);

            try
            {
                // Step 4: Get account info. It contains users, keys, groups, vault info and other stuff.
                //         Not the actual vault data though. That is requested separately.
                var accountInfo = GetAccountInfo(sessionKey, jsonHttp);

                // Step 5: Get all the keysets in one place. The original code is quite hairy around this
                //         topic, so it's not very clear if these keysets should be merged with anything else
                //         or it's enough to just use these keys. For now we gonna ignore other keys and
                //         see if it's enough.
                var keysets = GetKeysets(sessionKey, jsonHttp);

                // Step 6: Derive and decrypt keys
                DecryptAllKeys(accountInfo, keysets, clientInfo, keychain);

                // Step 7: Get and decrypt vaults
                var vaults = GetVaults(accountInfo, sessionKey, keychain, jsonHttp);

                // Done
                return vaults;
            }
            finally
            {
                // TODO: If SignOut throws an exception it will hide the exception
                //       thrown in the try block above (if any). This will hide the
                //       original problem and thus will make it harder to diagnose
                //       the issue.

                // Last step: Make sure to sign out in any case
                SignOut(jsonHttp);
            }
        }

        internal static string GetApiUrl(string domain)
        {
            return string.Format("https://{0}/api", domain);
        }

        internal static JsonHttpClient MakeJsonClient(IHttpClient http,
                                                      string baseUrl,
                                                      string sessionId = null)
        {
            var jsonHttp = new JsonHttpClient(http, baseUrl);
            jsonHttp.Headers["X-AgileBits-Client"] = ClientId;

            if (sessionId != null)
                jsonHttp.Headers["X-AgileBits-Session-ID"] = sessionId;

            return jsonHttp;
        }

        internal static JsonHttpClient MakeJsonClient(JsonHttpClient jsonHttp,
                                                      string sessionId = null)
        {
            return MakeJsonClient(jsonHttp.Http, jsonHttp.BaseUrl, sessionId);
        }

        internal static Session StartNewSession(ClientInfo clientInfo, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Get(string.Format("v2/auth/{0}/{1}/{2}/{3}",
                                                      clientInfo.Username,
                                                      clientInfo.AccountKey.Format,
                                                      clientInfo.AccountKey.Uuid,
                                                      clientInfo.Uuid));
            var status = response.StringAt("status");
            switch (status)
            {
            case "ok":
                var session = Session.Parse(response);
                if (session.KeyUuid != clientInfo.AccountKey.Uuid)
                    throw new ClientException(ClientException.FailureReason.IncorrectCredentials,
                                              "The account key is incorrect");
                return session;
            case "device-not-registered":
                RegisterDevice(clientInfo, MakeJsonClient(jsonHttp, response.StringAt("sessionID")));
                break;
            case "device-deleted":
                ReauthorizeDevice(clientInfo, MakeJsonClient(jsonHttp, response.StringAt("sessionID")));
                break;
            default:
                throw new ClientException(
                    ClientException.FailureReason.InvalidResponse,
                    string.Format(
                        "Failed to start a new session, unsupported response status '{0}'",
                        status));
            }

            return StartNewSession(clientInfo, jsonHttp);
        }

        internal static void RegisterDevice(ClientInfo clientInfo, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post("v1/device",
                                         new Dictionary<string, object>
                                         {
                                             {"uuid", clientInfo.Uuid},
                                             {"clientName", ClientName},
                                             {"clientVersion", ClientVersion},
                                         });

            if (response.IntAt("success") != 1)
                throw new ClientException(ClientException.FailureReason.RespondedWithError,
                                          string.Format("Failed to register the device '{0}'",
                                                        clientInfo.Uuid));
        }

        internal static void ReauthorizeDevice(ClientInfo clientInfo, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Put(string.Format("v1/device/{0}/reauthorize", clientInfo.Uuid));

            if (response.IntAt("success") != 1)
                throw new ClientException(ClientException.FailureReason.RespondedWithError,
                                          string.Format("Failed to reauthorize the device '{0}'",
                                                        clientInfo.Uuid));
        }

        internal static void VerifySessionKey(ClientInfo clientInfo,
                                              Session session,
                                              AesKey sessionKey,
                                              JsonHttpClient jsonHttp)
        {
            try
            {
                var response = PostEncryptedJson(
                    "v2/auth/verify",
                    new
                    {
                        sessionID = session.Id,
                        clientVerifyHash = Crypto.CalculateClientHash(clientInfo, session),
                        client = ClientId
                    },
                    sessionKey,
                    jsonHttp);

                // Just to verify that it's a valid JSON and it has some keys.
                // Technically it should have failed by now either in decrypt or JSON parse
                response.StringAt("userUuid");
            }
            catch (ClientException e)
            {
                // This is a quite ugly attempt at handling a very special case.
                // When this specific request fails with 400, the response contains
                // the error code. It seems 102 means invalid credentials.

                // TODO: Write a test for this case.

                if (e.Reason != ClientException.FailureReason.NetworkError)
                    throw;

                var web = e.InnerException as WebException;
                if (web == null)
                    throw;

                var response = web.Response as HttpWebResponse;
                if (response == null)
                    throw;

                var stream = response.GetResponseStream();
                if (stream == null)
                    throw;

                stream.Position = 0;
                var text = new System.IO.StreamReader(stream).ReadToEnd();

                var json = JObject.Parse(text);
                if (json.IntAt("errorCode", 0) == 102)
                    throw new ClientException(ClientException.FailureReason.IncorrectCredentials,
                                              "Username, password or account key is incorrect",
                                              e);

                throw;
            }
        }

        internal static JObject GetAccountInfo(AesKey sessionKey, JsonHttpClient jsonHttp)
        {
            return GetEncryptedJson("v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults", sessionKey, jsonHttp);
        }

        internal static JObject GetKeysets(AesKey sessionKey, JsonHttpClient jsonHttp)
        {
            return GetEncryptedJson("v1/account/keysets", sessionKey, jsonHttp);
        }

        internal static Vault[] GetVaults(JToken accountInfo,
                                          AesKey sessionKey,
                                          Keychain keychain,
                                          JsonHttpClient jsonHttp)
        {
            return accountInfo.At("vaults")
                .Where(IsVaultEntryValid)
                .Select(i => GetVault(i, sessionKey, keychain, jsonHttp))
                .ToArray();
        }

        internal static bool IsVaultEntryValid(JToken json)
        {
            return json.StringAt("uuid", "") != "";
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
            var response = GetEncryptedJson(string.Format("v1/vault/{0}/0/items", id),
                                            sessionKey,
                                            jsonHttp);
            return response.At("items", new JArray()).Select(i => ParseAccount(i, keychain)).ToArray();
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
            var response = jsonHttp.Put("v1/session/signout");
            if (response.IntAt("success") != 1)
                throw new ClientException(ClientException.FailureReason.RespondedWithError,
                                          "Failed to sign out");
        }

        internal static void DecryptAllKeys(JToken accountInfo,
                                            JToken keysets,
                                            ClientInfo clientInfo,
                                            Keychain keychain)
        {
            DecryptKeysets(keysets.At("keysets"), clientInfo, keychain);
            DecryptVaultKeys(accountInfo.At("me/vaultAccess"), keychain);
        }

        internal static void DecryptKeysets(JToken keysets, ClientInfo clientInfo, Keychain keychain)
        {
            var sorted = keysets
                .OrderByDescending(i => i.StringAt("encryptedBy") == MasterKeyId) // everything with "mp" goes first
                .ThenByDescending(i => i.IntAt("sn"))                             // and then is sorted by "sn"
                .ToArray();

            if (sorted[0].StringAt("encryptedBy") != MasterKeyId)
                throw ExceptionFactory.MakeInvalidOperation(
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
            // TODO: Check if the Unicode normalization is the correct one. This could be done
            //       by either trying to call the original JS functions in the browser console
            //       or by changing to some really weird password and trying to log in.

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
