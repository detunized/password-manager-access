// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;

namespace PasswordManagerAccess.NordPass;

public record Account(string Id, string Name, string Username, string Password, string[] Urls, string Note, string Folder, CustomField[] CustomFields)
{
    public string Url => Urls.FirstOrDefault() ?? "";
}

public record CustomField(string Name, string Value);
