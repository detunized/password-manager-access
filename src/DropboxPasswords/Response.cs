// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

// In this module everything is initialized via Reflection and the code analysis tools get confused
#pragma warning disable 8618

using System.Collections.Generic;
using Newtonsoft.Json;

namespace PasswordManagerAccess.DropboxPasswords
{
    internal static class Response
    {
        public class OAuth2Token
        {
            [JsonProperty("token_type", Required = Required.Always)]
            public readonly string TokenType;

            [JsonProperty("access_token", Required = Required.Always)]
            public readonly string AccessToken;

            [JsonProperty("scope")]
            public readonly string Scope;

            [JsonProperty("uid")]
            public readonly string Uid;

            [JsonProperty("account_id")]
            public readonly string AccountId;
        }

        public class AccountInfo
        {
            [JsonProperty("account_id", Required = Required.Always)]
            public readonly string AccountId;

            [JsonProperty("email", Required = Required.Always)]
            public readonly string Email;

            [JsonProperty("disabled", Required = Required.Always)]
            public readonly bool Disabled;

            [JsonProperty("root_info", Required = Required.Always)]
            public readonly RootInfo RootInfo;
        }

        public class RootInfo
        {
            [JsonProperty("root_namespace_id", Required = Required.Always)]
            public readonly string RootNamespaceId;
        }

        public class EnrollStatus
        {
            [JsonProperty("status", Required = Required.Always)]
            public readonly Status Status;

            [JsonProperty("active_keyset_name", Required = Required.Always)]
            public readonly string ActiveKeysetName;

            [JsonProperty("device_hid", Required = Required.Always)]
            public readonly string DeviceHid;
        }

        public class Status
        {
            [JsonProperty(".tag", Required = Required.Always)]
            public readonly string Tag;
        }

        public class Error
        {
            [JsonProperty("error_summary", Required = Required.Always)]
            public readonly string Summary;

            [JsonProperty("error", Required = Required.Always)]
            public readonly Status Status;
        }

        public class Features
        {
            [JsonProperty("eligibility", Required = Required.Always)]
            public readonly Eligibility Eligibility;
        }

        public readonly struct Eligibility
        {
            [JsonProperty(".tag", Required = Required.Always)]
            public readonly string Tag;

            [JsonProperty("passwords_path_root", Required = Required.Always)]
            public readonly string RootPath;
        }

        public class BoltInfo
        {
            [JsonProperty("app_id", Required = Required.Always)]
            public readonly string AppId;

            [JsonProperty("unique_id", Required = Required.Always)]
            public readonly string UniqueId;

            [JsonProperty("revision", Required = Required.Always)]
            public readonly string Revision;

            [JsonProperty("token", Required = Required.Always)]
            public readonly string Token;
        }

        // TODO: Remove this in favor of dynamic access.
        public class SubscriptionUpdate
        {
            [JsonProperty("channel_payloads")]
            public readonly ChannelPayload[] ChannelPayloads;
        }

        public class ChannelPayload
        {
            [JsonProperty("channel_state")]
            public readonly ChannelState ChannelState;

            [JsonProperty("payloads")]
            public readonly Payload[] Payloads;
        }

        public class ChannelState
        {
            [JsonProperty("channel_id")]
            public readonly ChannelId ChannelId;

            [JsonProperty("revision")]
            public readonly string Revision;

            [JsonProperty("token")]
            public readonly string Token;
        }

        public class ChannelId
        {
            [JsonProperty("app_id")]
            public readonly string AppId;

            [JsonProperty("unique_id")]
            public readonly string UniqueId;
        }

        public class Payload
        {
            [JsonProperty("revision")]
            public readonly string Revision;

            [JsonProperty("payload")]
            public readonly PayloadDetails PayloadDetails;
        }

        public class PayloadDetails
        {
            [JsonProperty("source_device_id")]
            public readonly string SourceDeviceId;

            [JsonProperty("target_device_id")]
            public readonly string TargetDeviceId;

            [JsonProperty("message_type")]
            public readonly int MessageType;

            [JsonProperty("encrypted_user_key_bundle")]
            public readonly EncryptedUserKeyBundle EncryptedUserKeyBundle;

            [JsonProperty("source_device_public_key")]
            public readonly string SourceDevicePublicKey;

            [JsonProperty("enroll_action")]
            public readonly string EnrollAction;

            [JsonProperty("notification_id")]
            public readonly string NotificationId;
        }

        public class EncryptedUserKeyBundle
        {
            [JsonProperty("encrypted_data")]
            public readonly string EncryptedDataBase64;

            [JsonProperty("nonce")]
            public readonly string NonceBase64;
        }

        public class RootFolder
        {
            [JsonProperty("entries", Required = Required.Always)]
            public readonly FolderEntry[] Entries;

            [JsonProperty("cursor", Required = Required.Always)]
            public readonly string Cursor;

            [JsonProperty("has_more", Required = Required.Always)]
            public readonly bool HasMore;
        }

        public readonly struct FolderEntry
        {
            [JsonProperty(".tag", Required = Required.Always)]
            public readonly string Tag;

            [JsonProperty("path_lower", Required = Required.Always)]
            public readonly string Path;

            [JsonProperty("is_downloadable", Required = Required.Always)]
            public readonly bool IsDownloadable;
        }

        public class EncryptedEntry
        {
            [JsonProperty("identifier", Required = Required.Always)]
            public readonly string Id;

            [JsonProperty("type", Required = Required.Always)]
            public readonly string Type;

            [JsonProperty("version", Required = Required.Always)]
            public readonly int Version;

            [JsonProperty("encryptedBundle", Required = Required.Always)]
            public readonly EncryptedBundle EncryptedBundle;
        }

        internal readonly struct EncryptedBundle
        {
            [JsonProperty("base64EncryptedData", Required = Required.Always)]
            public readonly string CiphertextBase64;

            [JsonProperty("base64Nonce", Required = Required.Always)]
            public readonly string NonceBase64;
        }

        internal class Keyset
        {
            [JsonProperty("mainFolderIdentifier", Required = Required.Always)]
            public readonly string MainFolderId;

            [JsonProperty("version", Required = Required.Always)]
            public readonly int Version;

            [JsonProperty("keyMap", Required = Required.Always)]
            public readonly Dictionary<string, Key> Keys;
        }

        internal readonly struct Key
        {
            [JsonProperty("base64SecretKey", Required = Required.Always)]
            public readonly string KeyBase64;

            [JsonProperty("deleted", Required = Required.Always)]
            public readonly bool Deleted;
        }

        internal class VaultFolder
        {
            [JsonProperty("identifier", Required = Required.Always)]
            public readonly string Id;

            [JsonProperty("name")]
            public readonly string Name;

            [JsonProperty("items", Required = Required.Always)]
            public readonly VaultFolderItem[] Items;
        }

        internal readonly struct VaultFolderItem
        {
            [JsonProperty("deleted", Required = Required.Always)]
            public readonly bool IsDeleted;

            [JsonProperty("identifier")]
            public readonly string Id;

            [JsonProperty("title")]
            public readonly string Name;

            [JsonProperty("username")]
            public readonly string Username;

            [JsonProperty("password")]
            public readonly string Password;

            [JsonProperty("site")]
            public readonly string Url;

            [JsonProperty("notes")]
            public readonly string Note;
        }
    }
}
