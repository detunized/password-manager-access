// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using TrueKey;

namespace Example
{
    class Program
    {
        private class Gui: TwoFactorAuth.Gui
        {
            public override Answer AskToWaitForEmail(string email, Answer[] validAnswers)
            {
                return Answer.Check;
            }

            public override Answer AskToWaitForOob(string name, string email, Answer[] validAnswers)
            {
                return Answer.Check;
            }

            public override Answer AskToChooseOob(string[] names, string email, Answer[] validAnswers)
            {
                return Answer.Device0;
            }
        }

        static void Main(string[] args)
        {
            // TODO: Read the credentials from a config file
            var username = "username@example.com";
            var password = "password";

            var vault = Vault.Open(username, password, new Gui());
        }
    }
}
