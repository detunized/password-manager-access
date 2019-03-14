// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Keeper
{
    public abstract class Ui
    {
        // To cancel return Passcode.Cancel
        public abstract Passcode ProvideGoogleAuthPasscode();

        // The UI will no longer be used and could be closed
        public abstract void Close();

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
    }
}
