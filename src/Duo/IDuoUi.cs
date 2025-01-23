// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Duo
{
    // TODO: Remove all of these types when done with the migration

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

    //
    // Internal
    //

    internal class DuoUiToAsyncUiAdapter(IDuoUi ui) : IDuoAsyncUi
    {
        public Task<OneOf<Choice, MfaMethod, Cancelled>> ChooseFactor(Device[] devices, MfaMethod[] otherMethods, CancellationToken cancellationToken)
        {
            var duoDevices = devices.Select(ToDuoDevice).ToArray();
            var choice = ui.ChooseDuoFactor(duoDevices);
            return Task.FromResult(
                choice == null ? IDuoAsyncUi.CancelChoice() : IDuoAsyncUi.Choice(ToDevice(choice.Device), ToFactor(choice.Factor), choice.RememberMe)
            );
        }

        public Task<OneOf<Passcode, Cancelled>> ProvidePasscode(Device device, CancellationToken cancellationToken)
        {
            var passcode = ui.ProvideDuoPasscode(ToDuoDevice(device));
            return Task.FromResult(passcode.IsNullOrEmpty() ? IDuoAsyncUi.CancelPasscode() : IDuoAsyncUi.Passcode(passcode));
        }

        public Task UpdateStatus(Status status, string text, CancellationToken cancellationToken)
        {
            ui.UpdateDuoStatus(ToDuoStatus(status), text);
            return Task.CompletedTask;
        }

        private static DuoFactor ToDuoFactor(Factor factor) =>
            factor switch
            {
                Factor.Push => DuoFactor.Push,
                Factor.Call => DuoFactor.Call,
                Factor.Passcode => DuoFactor.Passcode,
                Factor.SendPasscodesBySms => DuoFactor.SendPasscodesBySms,
                _ => throw new ArgumentOutOfRangeException(nameof(factor), factor, "Unknown factor"),
            };

        private static DuoDevice ToDuoDevice(Device device) => new(device.Id, device.Name, device.Factors.Select(ToDuoFactor).ToArray());

        private static Factor ToFactor(DuoFactor factor) =>
            factor switch
            {
                DuoFactor.Push => Factor.Push,
                DuoFactor.Call => Factor.Call,
                DuoFactor.Passcode => Factor.Passcode,
                DuoFactor.SendPasscodesBySms => Factor.SendPasscodesBySms,
                _ => throw new ArgumentOutOfRangeException(nameof(factor), factor, "Unknown factor"),
            };

        private static Device ToDevice(DuoDevice device) => new(device.Id, device.Name, device.Factors.Select(ToFactor).ToArray());

        private static DuoStatus ToDuoStatus(Status status) =>
            status switch
            {
                Status.Success => DuoStatus.Success,
                Status.Error => DuoStatus.Error,
                Status.Info => DuoStatus.Info,
                _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown status"),
            };
    }
}
