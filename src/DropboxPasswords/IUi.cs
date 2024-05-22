// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.DropboxPasswords
{
    public interface IUi
    {
        // Returns the redirect URL with the code. null if canceled or errored.
        string PerformOAuthLogin(string url, string redirectUrl);

        // Tell the user that the enrollment request is about to be sent to other enrolled devices.
        // Could be used to tell the user to prepare their devices, like opening the browser extension to make sure
        // it is ready to receive the request. The list of devices is unfortunately not available at this point.
        void WillSendEnrollRequest();

        // Tell the user that the enrollment request has been sent to other enrolled devices.
        void EnrollRequestSent(string[] deviceNames);

        enum Action
        {
            KeepWaiting,
            ResendRequest,
            Cancel,
        }

        // We waited for the user to confirm the enrollment on another device and it timed out.
        // Chances are the user didn't see the request. Ask what to do next.
        // Return:
        //   - Action.KeepWaiting to do another long poll and keep waiting
        //   - Action.ResendRequest to resend the request and keep waiting
        //   - Action.Cancel to cancel the enrollment and abort with an error
        Action AskForNextAction();
    }
}
