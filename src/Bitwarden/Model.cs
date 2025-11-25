// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;
using R = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Bitwarden;

#nullable enable
// TODO: Finish migration to Model with records
internal static class Model
{
    public record FolderList([JsonProperty("data", Required = Required.Always)] R.Folder[] Folders);

    public record CollectionList([JsonProperty("data", Required = Required.Always)] R.Collection[] Collections);
}
#nullable restore
