// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace LastPass
{
    public abstract class Ui
    {
        // TODO: Think about how to deal with the cancellation.
        public enum SecondFactorMethod
        {
            GoogleAuth,
            Yubikey,
            // TODO: See which other methods should be supported.
        }

        public enum OutOfBandMethod
        {
            LastPassAuth,
            Toopher,
            Duo,
        }

        // Should always a valid string. Cancellation is not supported yet.
        public abstract string ProvideSecondFactorPassword(SecondFactorMethod method);

        // Should return immediately to allow the login process to continue. Once the OOB is approved
        // or declined by the user the library will return the result or throw an error.
        // Cancellation is not supported yet.
        public abstract void AskToApproveOutOfBand(OutOfBandMethod method);
    }
}
