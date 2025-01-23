// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Duo
{
    internal record DuoResult(string Code, string State, bool RememberMe)
    {
        // This is returned what the V4 URL returns a redirect to the V1 api. This could happen when the traditional
        // prompt is enabled in the Duo admin panel.
        public static readonly DuoResult RedirectToV1 = new("redirect-to-v1", "redirect-to-v1", false);
    }
}
