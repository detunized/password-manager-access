// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Globalization;
using System.Runtime.CompilerServices;

namespace PasswordManagerAccess.Test;

static class ModuleInitializer
{
    [ModuleInitializer]
    internal static void Init()
    {
        // Pin the culture for the entire test assembly so that locale-dependent
        // formatting (dates, numbers, etc.) is deterministic across platforms.
        CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
    }
}
