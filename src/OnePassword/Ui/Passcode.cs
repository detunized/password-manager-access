// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword.Ui;

public class Passcode
{
    public static readonly Passcode Cancel = new Passcode("cancel", false);

    public readonly string Code;
    public readonly bool RememberMe;

    public Passcode(string code, bool rememberMe)
    {
        Code = code;
        RememberMe = rememberMe;
    }
}
