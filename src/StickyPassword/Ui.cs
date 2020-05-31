// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.StickyPassword.Ui
{
    public interface IUi
    {
        Passcode ProvideEmailPasscode();
    }

    public class Passcode
    {
        public static readonly Passcode Cancel = new Passcode("cancel");

        public readonly string Code;

        public Passcode(string code)
        {
            Code = code;
        }
    }
}
