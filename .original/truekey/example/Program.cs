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
        }
    }
}
