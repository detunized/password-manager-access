// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
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
            // Step 1: Request to initiate a new session
            var session = StartNewSession(clientInfo);

            // Step 2: Perform SRP exchange
            var sessionKey = Srp.Perform(clientInfo, session, _http);

            // Step 3: Verify the key with the server
            VerifySessionKey(session, sessionKey);

            // Step 4: Get account info. It contains users, keys, groups, vault info and other stuff.
            //         Not the actual vault data though. That is requested separately.
            var accountInfo = GetAccountInfo(sessionKey);

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

        internal JObject GetJson(string endpoint, AesKey sessionKey)
        {
            // TODO: Set X-AgileBits-* headers
            return DecryptAndParse(_http.Get(endpoint), sessionKey);
        }

        internal JObject PostJson(string endpoint, object parameters, AesKey sessionKey)
        {
            var payload = JsonConvert.SerializeObject(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());

            // TODO: Set X-AgileBits-* headers
            var response = _http.Post(endpoint, new Dictionary<string, object>
            {
                {"kid", encryptedPayload.KeyId},
                {"enc", encryptedPayload.Scheme},
                {"cty", encryptedPayload.Container},
                {"iv", encryptedPayload.Iv.ToBase64()},
                {"data", encryptedPayload.Ciphertext.ToBase64()},
            });

            return DecryptAndParse(response, sessionKey);
        }

        internal JObject DecryptAndParse(JObject response, AesKey sessionKey)
        {
            var encrypted = new Encrypted(keyId: response.StringAt("kid"),
                                          scheme: response.StringAt("enc"),
                                          container: response.StringAt("cty"),
                                          iv: response.StringAt("iv").Decode64(),
                                          ciphertext: response.StringAt("data").Decode64());
            var decrypted = sessionKey.Decrypt(encrypted);

            return JObject.Parse(decrypted.ToUtf8());
        }

        //
        // Private
        //

        private readonly JsonHttpClient _http;
    }
}
