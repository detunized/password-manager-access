// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.TrueKey;
using PasswordManagerAccess.Example.Common;

namespace PasswordManagerAccess.Example.TrueKey
{
    public static class Program
    {
        private class TextUi: Ui
        {
            public override Answer AskToWaitForEmail(string email, Answer[] validAnswers)
            {
                var answer = AskForAnswer(string.Format(
                    "A verification email is sent to '{0}'.\n" +
                    "Please check the inbox, confirm and then press enter.\n" +
                    "Enter 'r' to resend the email to '{0}'.", email));

                switch (answer.ToLowerInvariant())
                {
                case "r":
                    return Answer.Resend;
                default:
                    return Answer.Check;
                }
            }

            public override Answer AskToWaitForOob(string name, string email, Answer[] validAnswers)
            {
                var answer = AskForAnswer(string.Format(
                    "A push message is sent to '{0}'.\n" +
                    "Please check, confirm and then press enter.\n" +
                    "Enter 'r' to resend the push message to '{0}'.\n" +
                    "Enter 'e' to send a verification email to '{1}' instead.", name, email));

                switch (answer.ToLowerInvariant())
                {
                case "r":
                    return Answer.Resend;
                case "e":
                    return Answer.Email;
                default:
                    return Answer.Check;
                }
            }

            public override Answer AskToChooseOob(string[] names, string email, Answer[] validAnswers)
            {
                var text = new List<string>(names.Length + 2)
                {
                    "Please choose the second factor method:"
                };
                text.AddRange(names.Select((name, index) => string.Format(
                    " - {0}: push message to '{1}'",
                    index + 1,
                    name)));
                text.Add(string.Format(" - e: verification email to '{0}'", email));

                for (;;)
                {
                    var answer = AskForAnswer(string.Join("\n", text));

                    if (answer == "e")
                        return Answer.Email;

                    int deviceIndex;
                    if (int.TryParse(answer, out deviceIndex))
                    {
                        deviceIndex -= 1;
                        if (deviceIndex >= 0 && deviceIndex < names.Length)
                            return Answer.Device0 + deviceIndex;
                    }

                    Console.WriteLine("Invalid input '{0}'", answer);
                }
            }

            private string AskForAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");

                var input = Console.ReadLine();
                return input == null ? "" : input.Trim();
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"], config["password"], new TextUi(), new PlainStorage());
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("{0}:\n" +
                                      "          id: {1}\n" +
                                      "        name: {2}\n" +
                                      "    username: {3}\n" +
                                      "    password: {4}\n" +
                                      "         url: {5}\n" +
                                      "        note: {6}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Note);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
