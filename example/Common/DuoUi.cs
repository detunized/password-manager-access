// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoAsyncUi : BaseAsyncUi, IDuoAsyncUi
    {
        public async Task<DuoChoice> ChooseDuoFactor(DuoDevice[] devices, CancellationToken cancellationToken)
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
                    return null;

                int choice;
                if (int.TryParse(answer, out choice))
                    foreach (var d in devices)
                    foreach (var f in d.Factors)
                        if (--choice == 0)
                            return new DuoChoice(d, f, await GetRememberMe(cancellationToken).ConfigureAwait(false));

                Console.WriteLine("Wrong input, try again");
            }
        }

        public async Task<string> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
        {
            return await GetAnswer($"Enter the passcode for {device.Name} {PressEnterToCancel}", cancellationToken).ConfigureAwait(false);
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
            return _asyncUi.ChooseDuoFactor(devices, CancellationToken.None).GetAwaiter().GetResult();
        }

        public string ProvideDuoPasscode(DuoDevice device)
        {
            return _asyncUi.ProvideDuoPasscode(device, CancellationToken.None).GetAwaiter().GetResult();
        }

        public void UpdateDuoStatus(DuoStatus status, string text)
        {
            _asyncUi.UpdateDuoStatus(status, text, CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}
