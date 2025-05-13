// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword;

public enum Region
{
    Global,
    Europe,
    Canada,
}

public static class Extensions
{
    public static string ToDomain(this Region region)
    {
        return region switch
        {
            Region.Global => "my.1password.com",
            Region.Europe => "my.1password.eu",
            Region.Canada => "my.1password.ca",
            _ => throw new InternalErrorException("The region is not valid"),
        };
    }
}
