// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace TrueKey
{
    public abstract class Gui
    {
        public enum Answer
        {
            Check,
            Resend,
            Email,
            Device0,
        }

        public abstract Answer AskToWaitForEmail(string email, Answer[] validAnswers);
        public abstract Answer AskToWaitForOob(string name, string email, Answer[] validAnswers);
        public abstract Answer AskToChooseOob(string[] names, string email, Answer[] validAnswers);
    }
}
