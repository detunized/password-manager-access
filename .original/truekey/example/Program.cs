// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using TrueKey;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Step 1: Register a new device and get a token and an id back.
            var deviceInfo = Remote.RegisetNewDevice("truekey-sharp");

            // Step 2: Parse the token to decode OTP information.
            var otpInfo = Remote.ParseClientToken(deviceInfo.Token);

            // Step 3: Validate the OTP info to make sure it's got only the
            //         things we support at the moment.
            Remote.ValidateOtpInfo(otpInfo);

            // Bundle up everything in one place
            var clientInfo = new Remote.ClientInfo("username@example.com", // TODO: Read username from a config file
                                                   "truekey-sharp",
                                                   deviceInfo,
                                                   otpInfo);

            // Step 4: auth step 1 gives us a transaction id to pass along to the next step
            var transactionId = Remote.AuthStep1(clientInfo);
        }
    }
}
