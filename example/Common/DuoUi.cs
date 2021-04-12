// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoUi: BaseUi, IDuoUi
    {
        public DuoChoice ChooseDuoFactor(DuoDevice[] devices) =>
            _ui.ChooseDuoFactor(devices).GetAwaiter().GetResult();

        public string ProvideDuoPasscode(DuoDevice device) =>
            _ui.ProvideDuoPasscode(device).GetAwaiter().GetResult();

        public void UpdateDuoStatus(DuoStatus status, string text) =>
            _ui.UpdateDuoStatus(status, text).GetAwaiter().GetResult();

        //
        // Private
        //

        private DuoUiAsync _ui = new DuoUiAsync();
    }

    public class DuoUiAsync: BaseUi, IDuoUiAsync
    {
        public async Task<DuoChoice> ChooseDuoFactor(DuoDevice[] devices)
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
                var answer = await GetAnswerAsync(prompt);

                // Blank means canceled by the user
                if (string.IsNullOrWhiteSpace(answer))
                    return null;

                int choice;
                if (int.TryParse(answer, out choice))
                    foreach (var d in devices)
                    foreach (var f in d.Factors)
                        if (--choice == 0)
                            return new DuoChoice(d, f, await GetRememberMeAsync());

                Console.WriteLine("Wrong input, try again");
            }
        }

        public async Task<string> ProvideDuoPasscode(DuoDevice device)
        {
            return await GetAnswerAsync($"Enter the passcode for {device.Name} {PressEnterToCancel}");
        }

        public Task UpdateDuoStatus(DuoStatus status, string text)
        {
            WriteLine($"Duo {status}: {text}", StatusToColor(status));
            return Task.CompletedTask;
        }

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
}
