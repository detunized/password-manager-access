// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoAsyncUi : BaseAsyncUi, IDuoAsyncUi
    {
        public async Task<OneOf<Choice, MfaMethod, Cancelled>> ChooseFactor(
            Device[] devices,
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        )
        {
            var prompt = $"Choose a factor you want to use {PressEnterToCancel}:\n\n";
            var index = 1;
            foreach (var d in devices)
            {
                prompt += $"{d.Name}\n";
                foreach (var f in d.Factors)
                {
                    prompt += $"  {index}. {f}\n";
                    index += 1;
                }
            }

            while (true)
            {
                var answer = await GetAnswer(prompt, cancellationToken).ConfigureAwait(false);

                // Blank means canceled by the user
                if (string.IsNullOrWhiteSpace(answer))
                    return IDuoAsyncUi.CancelChoice();

                int choice;
                if (int.TryParse(answer, out choice))
                    foreach (var d in devices)
                    foreach (var f in d.Factors)
                        if (--choice == 0)
                            return IDuoAsyncUi.Choice(d, f, await GetRememberMe(cancellationToken).ConfigureAwait(false));

                Console.WriteLine("Wrong input, try again");
            }
        }

        public async Task<OneOf<Passcode, Cancelled>> ProvidePasscode(Device device, CancellationToken cancellationToken)
        {
            var answer = await GetAnswer($"Enter the passcode for {device.Name} {PressEnterToCancel}", cancellationToken).ConfigureAwait(false);
            return answer == "" ? IDuoAsyncUi.CancelPasscode() : IDuoAsyncUi.Passcode(answer);
        }

        public Task UpdateStatus(Status status, string text, CancellationToken cancellationToken)
        {
            WriteLine($"Duo {status}: {text}", StatusToColor(status));
            return Task.CompletedTask;
        }

        //
        // Private
        //

        private static ConsoleColor StatusToColor(Status status)
        {
            switch (status)
            {
                case Status.Success:
                    return ConsoleColor.Green;
                case Status.Error:
                    return ConsoleColor.Red;
                case Status.Info:
                    return ConsoleColor.Blue;
            }

            throw new ArgumentException("Unknown status");
        }
    }

    // TODO: Remove this once the migration is complete
    public class DuoUi : BaseUi, IDuoUi
    {
        private readonly DuoAsyncUi _asyncUi = new();

        public DuoChoice ChooseDuoFactor(DuoDevice[] devices)
        {
            var r = _asyncUi.ChooseFactor(devices.Select(ToDevice).ToArray(), [], CancellationToken.None).GetAwaiter().GetResult();

            if (r.IsB)
                throw new NotImplementedException("MFA selection is not supported");

            if (r.IsC)
                return null;

            return new DuoChoice(ToDuoDevice(r.A.Device), ToDuoFactor(r.A.Factor), r.A.RememberMe);
        }

        public string ProvideDuoPasscode(DuoDevice device)
        {
            var r = _asyncUi.ProvidePasscode(ToDevice(device), CancellationToken.None).GetAwaiter().GetResult();

            if (r.IsB)
                return null;

            return r.A.Code;
        }

        public void UpdateDuoStatus(DuoStatus status, string text)
        {
            _asyncUi.UpdateStatus(ToStatus(status), text, CancellationToken.None).GetAwaiter().GetResult();
        }

        //
        // Private
        //

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

        private static Status ToStatus(DuoStatus status) =>
            status switch
            {
                DuoStatus.Success => Status.Success,
                DuoStatus.Error => Status.Error,
                DuoStatus.Info => Status.Info,
                _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown status"),
            };
    }
}
