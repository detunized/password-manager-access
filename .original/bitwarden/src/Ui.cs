// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace Bitwarden
{
    public abstract class Ui
    {
        public class Passcode
        {
            public readonly string Code;
            public readonly bool RememberMe;

            public Passcode(string code, bool rememberMe)
            {
                Code = code;
                RememberMe = rememberMe;
            }
        }

        // To cancel any of these return null
        public abstract Passcode ProvideGoogleAuthPasscode();
        public abstract Passcode ProvideEmailPasscode(string emailHint);
        public abstract Passcode ProvideYubiKeyPasscode();

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

        public class DuoChoice
        {
            public readonly DuoDevice Device;
            public readonly DuoFactor Factor;
            public readonly bool RememberMe;

            public DuoChoice(DuoDevice device, DuoFactor factor, bool rememberMe)
            {
                Device = device;
                Factor = factor;
                RememberMe = rememberMe;
            }
        }

        public enum DuoStatus
        {
            Success,
            Error,
            Info,
        }

        // To cancel return null
        public abstract DuoChoice ChooseDuoFactor(DuoDevice[] devices);

        // To cancel return null or blank
        public abstract string ProvideDuoPasscode(DuoDevice device);

        // This updates the UI with the messages from the server.
        // The implementation is optional as this is purely informational.
        public virtual void UpdateDuoStatus(DuoStatus status, string text) { }
    }
}
