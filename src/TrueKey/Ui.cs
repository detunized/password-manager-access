// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.TrueKey
{
    // This is the interface to be implemented by the user of the library.
    // It's used to provide answers for the interactive two factor login
    // process. The process is meant to interact with the user but it doesn't
    // mean it has to. The implementation could simply return the first answer
    // or something else like that. Have to be careful with the "wait" states
    // though, as the answer should only come after the user is confirmed the
    // second factor action, like clicked a button in the email or confirmed
    // on the phone.
    // The only reason this is a class and not an interface is because there's
    // no way to have an enum inside an interface.
    public abstract class Ui
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
