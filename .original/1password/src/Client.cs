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

        public Vault OpenVault(ClientInfo clientInfo)
        {
            var keychain = new Keychain();

            // Step 1: Request to initiate a new session
            var session = StartNewSession(clientInfo);

            // Step 2: Perform SRP exchange
            var sessionKey = Srp.Perform(clientInfo, session, _http);
            keychain.Add(sessionKey);

            // Step 3: Verify the key with the server
            VerifySessionKey(session, sessionKey);

            // Step 4: Get account info. It contains users, keys, groups, vault info and other stuff.
            //         Not the actual vault data though. That is requested separately.
            var accountInfo = GetAccountInfo(sessionKey);

            // Step 5: Derive and decrypt keys
            DecryptKeysets(accountInfo.At("user/keysets"), clientInfo, keychain);

            return new Vault();
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
            var endpoint = string.Join("/", "auth", clientInfo.Username, clientInfo.Uuid, "-");
            var response = _http.Get(endpoint);
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
            var response = PostJson("auth/verify", new {sessionID = session.Id}, sessionKey);

            // Just to verify that it's a valid JSON and it has some keys.
            // Technically it should have failed by now either in decrypt or JSON parse
            response.StringAt("userUuid");
        }

        internal JObject GetAccountInfo(AesKey sessionKey)
        {
            return GetJson("accountpanel", sessionKey);
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

        internal static void DecryptKeyset(JToken keyset, Keychain keychain)
        {
            keychain.Add(AesKey.Parse(Decrypt(keyset.At("encSymKey"), keychain)));
            // TODO: Parse RSA key
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

        internal JObject GetJson(string endpoint, AesKey sessionKey)
        {
            // TODO: Set X-AgileBits-* headers
            return Decrypt(_http.Get(endpoint), sessionKey);
        }

        internal JObject PostJson(string endpoint, object parameters, AesKey sessionKey)
        {
            var payload = JsonConvert.SerializeObject(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());

            // TODO: Set X-AgileBits-* headers
            var response = _http.Post(endpoint, encryptedPayload.ToDictionary());

            return Decrypt(response, sessionKey);
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
