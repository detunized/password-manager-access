// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.RoboForm
{
    public abstract class Ui
    {
        public class SecondFactorPassword
        {
            public readonly string Password;
            public readonly bool RememberDevice;

            public SecondFactorPassword(string password, bool rememberDevice)
            {
                Password = password;
                RememberDevice = rememberDevice;
            }
        }

        // TODO: Support null to cancel
        public abstract SecondFactorPassword ProvideSecondFactorPassword(string kind);
    }
}
