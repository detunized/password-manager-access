// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.ZohoVault
{
    public class Settings
    {
        // When set to true the session cookies will be saved to the secure storage and logout will not be performed at the end.
        // This allows a subsequent request to reuse the previous session without doing a full login. Zoho limits the number
        // of full logins to 20 per day.
        public bool KeepSession { get; set; } = true;
    }
}
