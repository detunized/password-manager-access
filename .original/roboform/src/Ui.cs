// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm
{
    public abstract class Ui
    {
        public struct SecondFactorPassword
        {
            public readonly string Password;
            public readonly bool RememberDevice;

            public SecondFactorPassword(string password, bool rememberDevice)
            {
                Password = password;
                RememberDevice = rememberDevice;
            }
        }

        public abstract SecondFactorPassword ProvideSecondFactorPassword(string kind);
    }
}
