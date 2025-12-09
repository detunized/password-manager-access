// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Bitwarden;

public class Organization
{
    public readonly string Id;
    public readonly string Name;

    public Organization(string id, string name)
    {
        Id = id;
        Name = name;
    }
}
