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

        public class DuoResponse
        {
            public readonly DuoDevice Device;
            public readonly DuoFactor Factor;
            public readonly string Response; // TODO: Rename to passcode

            public DuoResponse(DuoDevice device, DuoFactor factor, string response)
            {
                Device = device;
                Factor = factor;
                Response = response;
            }
        }

        // To cancel return null
        public abstract DuoResponse ProvideDuoResponse(DuoDevice[] devices);

        public enum DuoStatus
        {
            Success,
            Error,
            Info,
        }

        public abstract void UpdateDuoStatus(DuoStatus status, string text);
    }
}
