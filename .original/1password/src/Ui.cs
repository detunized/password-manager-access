// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    public abstract class Ui
    {
        // Return null or blank to cancel
        public abstract string ProviceGoogleAuthenticatorCode();
    }
}
