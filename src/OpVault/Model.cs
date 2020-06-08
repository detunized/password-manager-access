// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.ComponentModel;
using Newtonsoft.Json;

namespace PasswordManagerAccess.OpVault.Model
{
    internal class Profile
    {
        [JsonProperty("salt", Required = Required.Always)]
        public readonly string Salt;

        [JsonProperty("iterations", Required = Required.Always)]
        public readonly int Iterations;

        [JsonProperty("masterKey", Required = Required.Always)]
        public readonly string MasterKey;

        [JsonProperty("overviewKey", Required = Required.Always)]
        public readonly string OverviewKey;
    }

    internal class Folder
    {
        [JsonProperty("uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("parent")]
        public readonly string ParentId;

        [JsonProperty("overview", Required = Required.Always)]
        public readonly string Overview;

        [JsonProperty("trashed",
                      Required = Required.DisallowNull,
                      DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue(false)]
        public readonly bool Deleted;
    }

    internal class FolderOverview
    {
        [JsonProperty("title", Required = Required.Always)]
        public readonly string Title;
    }

    internal class Item
    {
        [JsonProperty("uuid", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("category")]
        public readonly string Category;

        [JsonProperty("folder")]
        public readonly string FolderId;

        [JsonProperty("k", Required = Required.Always)]
        public readonly string Key;

        [JsonProperty("o", Required = Required.Always)]
        public readonly string Overview;

        [JsonProperty("d", Required = Required.Always)]
        public readonly string Details;

        [JsonProperty("trashed",
                      Required = Required.DisallowNull,
                      DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue(false)]
        public readonly bool Deleted;
    }

    internal class ItemOverview
    {
        [JsonProperty("title")]
        public readonly string Title;

        [JsonProperty("url")]
        public readonly string Url;
    }

    internal class ItemDetails
    {
        [JsonProperty("notesPlain")]
        public readonly string Notes;

        [JsonProperty("fields")]
        public readonly ItemField[] Fields;
    }

    internal class ItemField
    {
        [JsonProperty("designation")]
        public readonly string Designation;

        [JsonProperty("value")]
        public readonly string Value;
    }
}
