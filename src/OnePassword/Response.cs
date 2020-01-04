// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.OnePassword.Response
{
    internal class NewSession
    {
        [JsonProperty(PropertyName = "status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty(PropertyName = "sessionID", Required = Required.Always)]
        public readonly string SessionId;

        [JsonProperty(PropertyName = "accountKeyFormat")]
        public readonly string KeyFormat;

        [JsonProperty(PropertyName = "accountKeyUuid")]
        public readonly string KeyUuid;

        [JsonProperty(PropertyName = "userAuth")]
        public readonly UserAuth Auth;
    }

    internal struct UserAuth
    {
        [JsonProperty(PropertyName = "method")]
        public readonly string Method;

        [JsonProperty(PropertyName = "alg")]
        public readonly string Algorithm;

        [JsonProperty(PropertyName = "iterations")]
        public readonly int Iterations;

        [JsonProperty(PropertyName = "salt")]
        public readonly string Salt;
    }

    internal struct SuccessStatus
    {
        [JsonProperty(PropertyName = "success", Required = Required.Always)]
        public readonly int Success;
    }

    internal class Encrypted
    {
        [JsonProperty(PropertyName = "kid", Required = Required.Always)]
        public readonly string KeyId;

        [JsonProperty(PropertyName = "enc", Required = Required.Always)]
        public readonly string Scheme;

        [JsonProperty(PropertyName = "cty", Required = Required.Always)]
        public readonly string Container;

        [JsonProperty(PropertyName = "iv")]
        public readonly string Iv;

        [JsonProperty(PropertyName = "data", Required = Required.Always)]
        public readonly string Ciphertext;
    }

    internal class AccountInfo
    {
        [JsonProperty(PropertyName = "me", Required = Required.Always)]
        public readonly MeInfo Me;

        [JsonProperty(PropertyName = "vaults", Required = Required.Always)]
        public readonly VaultInfo[] Vaults;
    }

    internal class MeInfo
    {
        [JsonProperty(PropertyName = "vaultAccess", Required = Required.Always)]
        public readonly VaultAccessInfo[] VaultAceess;
    }

    internal class VaultAccessInfo
    {
        [JsonProperty(PropertyName = "vaultUuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty(PropertyName = "acl", Required = Required.Always)]
        public readonly int Acl;

        [JsonProperty(PropertyName = "encVaultKey", Required = Required.Always)]
        public readonly Encrypted EncryptedKey;
    }

    internal class VaultInfo
    {
        [JsonProperty(PropertyName = "uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty(PropertyName = "encAttrs", Required = Required.Always)]
        public readonly Encrypted Attributes;
    }

    internal class KeysetsInfo
    {
        [JsonProperty(PropertyName = "keysets", Required = Required.Always)]
        public readonly KeysetInfo[] Keysets;
    }

    internal class KeysetInfo
    {
        [JsonProperty(PropertyName = "encryptedBy", Required = Required.Always)]
        public readonly string EncryptedBy;

        [JsonProperty(PropertyName = "sn", Required = Required.Always)]
        public readonly int SerialNumber;

        [JsonProperty(PropertyName = "encSymKey", Required = Required.Always)]
        public readonly KeyDerivationInfo KeyOrMasterKey;

        [JsonProperty(PropertyName = "encPriKey", Required = Required.Always)]
        public readonly Encrypted PrivateKey;
    }

    // All these fields here are optional because for the master key and the master key only we have
    // more fields. For the master key these fields are not optional, but there's no way to express
    // this with attributes.
    internal class KeyDerivationInfo : Encrypted
    {
        [JsonProperty(PropertyName = "alg")]
        public readonly string Algorithm;

        [JsonProperty(PropertyName = "p2s")]
        public readonly string Salt;

        [JsonProperty(PropertyName = "p2c")]
        public readonly int Iterations;
    }
}
