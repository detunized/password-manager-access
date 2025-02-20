// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Duo
{
    // TODO: Remove this when done with the migration
    public interface IDuoUi
    {
        // To cancel return null
        DuoChoice ChooseDuoFactor(DuoDevice[] devices);

        // To cancel return null or blank
        string ProvideDuoPasscode(DuoDevice device);

        // This updates the UI with the messages from the server.
        void UpdateDuoStatus(DuoStatus status, string text);
    }

    //
    // Internal
    //

    internal class DuoUiToAsyncUiAdapter(IDuoUi ui) : IDuoAsyncUi
    {
        public Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(
            DuoDevice[] devices,
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        )
        {
            var choice = ui.ChooseDuoFactor(devices);
            return Task.FromResult(choice == null ? IDuoAsyncUi.CancelChoice() : IDuoAsyncUi.Choice(choice.Device, choice.Factor, choice.RememberMe));
        }

        public Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
        {
            var passcode = ui.ProvideDuoPasscode(device);
            return Task.FromResult(passcode.IsNullOrEmpty() ? IDuoAsyncUi.CancelPasscode() : IDuoAsyncUi.Passcode(passcode));
        }

        public Task DuoDone(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken)
        {
            ui.UpdateDuoStatus(status, text);
            return Task.CompletedTask;
        }
    }
}
