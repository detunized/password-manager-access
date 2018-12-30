// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace Bitwarden
{
    public abstract class Ui
    {
        // To cancel any of these return a blank string or null
        public abstract string ProvideGoogleAuthCode();
        public abstract string ProvideEmailCode(string email);
        public abstract string ProvideYubiKeyCode();

        //
        // Duo
        //

        public enum DuoFactor
        {
            Push,
            Call,
            Passcode,
            SendPasscodesBySms,
        }

        public class DuoDevice
        {
            public readonly string Id;
            public readonly string Name;
            public readonly DuoFactor[] Factors;

            public DuoDevice(string id, string name, DuoFactor[] factors)
            {
                Id = id;
                Name = name;
                Factors = factors;
            }
        }

        // To cancel return null device and any factor
        public abstract (DuoDevice Device, DuoFactor Factor) ChooseDuoFactor(DuoDevice[] devices);

        // To cancel return null or blank
        public abstract string ProvideDuoPasscode(DuoDevice device);

        public enum DuoStatus
        {
            Success,
            Error,
            Info,
        }

        public abstract void UpdateDuoStatus(DuoStatus status, string text);
    }
}
