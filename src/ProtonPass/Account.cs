// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;

namespace PasswordManagerAccess.ProtonPass
{
    public class Account
    {
        public string Id { get; internal set; } = "";
        public string Name { get; internal set; } = "";
        public string Email { get; internal set; } = "";
        public string Username { get; internal set; } = "";
        public string Password { get; internal set; } = "";
        public string[] Urls { get; internal set; } = Array.Empty<string>();
        public string Totp { get; internal set; } = "";
        public string Note { get; internal set; } = "";
    }
}
