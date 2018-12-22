// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace Bitwarden
{
    // TODO: Think about how to deal with the cancellation.
    public abstract class Ui
    {
        // Should always return a valid string. Cancellation is not supported yet.
        public abstract string ProvideGoogleAuthCode();
        public abstract string ProvideEmailCode(string email);
        public abstract string ProvideYubiKeyCode();
    }
}
