// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoAsyncUi : BaseAsyncUi, IDuoAsyncUi
    {
        public async Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(
            DuoDevice[] devices,
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

            var otherMfaMethodStartIndex = index;
            if (otherMethods.Length > 0)
            {
                prompt += "\nOr choose a different MFA method:\n";
                foreach (var m in otherMethods)
                {
                    prompt += $"  {index}. {m}\n";
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
                {
                    if (choice >= otherMfaMethodStartIndex)
                        return otherMethods[choice - otherMfaMethodStartIndex];

                    foreach (var d in devices)
                    foreach (var f in d.Factors)
                        if (--choice == 0)
                            return IDuoAsyncUi.Choice(d, f, await GetRememberMe(cancellationToken).ConfigureAwait(false));
                }

                Console.WriteLine("Wrong input, try again");
            }
        }

        public async Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
        {
            var answer = await GetAnswer($"Enter the passcode for {device.Name} {PressEnterToCancel}", cancellationToken).ConfigureAwait(false);
            return answer == "" ? IDuoAsyncUi.CancelPasscode() : IDuoAsyncUi.Passcode(answer);
        }

        public Task DuoDone(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken)
        {
            WriteLine($"Duo {status}: {text}", StatusToColor(status));
            return Task.CompletedTask;
        }

        //
        // Private
        //

        private static ConsoleColor StatusToColor(DuoStatus status)
        {
            switch (status)
            {
                case DuoStatus.Success:
                    return ConsoleColor.Green;
                case DuoStatus.Error:
                    return ConsoleColor.Red;
                case DuoStatus.Info:
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
            var r = _asyncUi.ChooseDuoFactor(devices, [], CancellationToken.None).GetAwaiter().GetResult();
            return r.Match(
                choice => new DuoChoice(choice.Device, choice.Factor, choice.RememberMe),
                _ => throw new NotImplementedException("MFA selection is not supported"),
                _ => null
            );
        }

        public string ProvideDuoPasscode(DuoDevice device)
        {
            var r = _asyncUi.ProvideDuoPasscode(device, CancellationToken.None).GetAwaiter().GetResult();
            return r.Match(passcode => passcode.Passcode, _ => null);
        }

        public void UpdateDuoStatus(DuoStatus status, string text)
        {
            _asyncUi.UpdateDuoStatus(status, text, CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}
