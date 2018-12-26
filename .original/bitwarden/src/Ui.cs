// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace Bitwarden
{
    // TODO: Think about how to deal with the cancellation.
    public abstract class Ui
    {
        // Should always return a valid string. Cancellation is not supported yet.
        public abstract string ProvideGoogleAuthCode();
        public abstract string ProvideEmailCode(string email);
        public abstract string ProvideYubiKeyCode();

        //
        // Duo
        //

        public enum DuoFactor
        {
            Push,
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
            public readonly string Response;

            public DuoResponse(DuoDevice device, DuoFactor factor, string response)
            {
                Device = device;
                Factor = factor;
                Response = response;
            }
        }

        public abstract DuoResponse ProvideDuoResponse(DuoDevice[] devices);
    }
}
