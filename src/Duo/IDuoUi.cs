// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Duo
{
    // Adds Duo functionality to the module-specific Ui class.
    public interface IDuoUi
    {
        // To cancel return null
        DuoChoice ChooseDuoFactor(DuoDevice[] devices);

        // To cancel return null or blank
        string ProvideDuoPasscode(DuoDevice device);

        // This updates the UI with the messages from the server.
        void UpdateDuoStatus(DuoStatus status, string text);
    }

    public enum DuoFactor
    {
        Push,
        Call,
        Passcode,
        SendPasscodesBySms,
    }

    public enum DuoStatus
    {
        Success,
        Error,
        Info,
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
}
