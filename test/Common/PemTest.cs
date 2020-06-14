// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class PemTest
    {
        [Fact]
        public void ParsePrivateKeyPkcs8_parses_openssl_generated_key()
        {
            // Generate with
            // $ openssl genpkey -out rsakey.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
            var key = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDl3KLYUotetBFN" +
                      "uzuCSQkUKIC/S7U1F7zjy2EzhbqRSQPi6TsCpDz+kal28hcXiPH1e3KlfeObmqoK" +
                      "8/OUdOtQzBqd5E8egoGBT3MKgKbJdFqQjI7hEAEX1E4S4WdM0wjLbaJ83PE1si1J" +
                      "eiEllBHrSnvV/Vgzrqx+j9zthUlmxTorhPj0ZPaz81q+ZFpBoqGw82V1D8Z0mlW9" +
                      "X3qxnSmXXXcx2VbPBbKbI4sHkL1KMZenvcofHqOzsu9KqcNyYyOvzgQabwnfyTvv" +
                      "p3fSu5WpNKDOxS3+HiPDkSwcf7ZggsOcGaZpTGebaDV9wG8FsUM/MhGQwjJsaAch" +
                      "C3R/KhbPAgMBAAECggEAcMaRdwT4sBw0qSiFh+SBecxtbm2cmFHvMOwl4ntoD8P9" +
                      "DiVT+HXQHy4kMOGSBs//tms80okzVLLLXthV166NjXS2UmUjlFp/Y4wxayO3sPtP" +
                      "O8BakX2iq6hULds9LWoU1IoTwKM+DRRAN96dyKwfJovCuji0P5chtm6q/DX6z1pi" +
                      "hnCfo3lFySKmEif/D55WbioVezRoDmBDw2zzxAl/OzVn37hVaxmnKzT5w6tJYmHQ" +
                      "ctilFMlKYQ6O+IUSphylwsD+P3Xszp1Am9SJGbIuDi63NW+5auwDdL40AjaIzXcU" +
                      "NoSmivEz/bMfIUeEeIcWM3Ph4Pmaly+Vdy7daX0YIQKBgQD66i6ChbYElRRojD2/" +
                      "GB9+jY2hQOe8Y8b75Lq2TNyNtB1wOWr0E04Ab2TitqW0SQVZZwUA4r0M3/leAxCj" +
                      "w1dmNlnC6obFgixBr3vMhL42xzxGam46887m8Hp3zR9WV2RJqOUkY58WReQ5d4ZR" +
                      "pwN2JCUMdIqTJFblrzlIbNDcxwKBgQDqhTnQ3ELAnJEF/4emO2IQZHjkqUYPjZUn" +
                      "NmD4zi/W6PYmbRF2uLs6lFwyEGNkO3FcIr7OQZniijcTRPyCFKyllAYzRDlg6Xe5" +
                      "GXvN1zDyyr9qfUCWDv7aec8fcG3Wlcl64HTYhWqTUDRICg80B0dwomYZwYmtw/cb" +
                      "TtnDSwgduQKBgQDwBrfJSmnNxmMIhCfJNyVhpb33pSRJtlUywCLQo4RU1hlXMsYa" +
                      "iKEUj3s92aV4amYAmSlTKJPaziM5iMsRLZvc/l8ts7aLGDSH/Xv7MHzZ4AvL/KJI" +
                      "KNUjXKZ7FjFFIkKgqD3Taq1T3DYvtyQ51f/cs0TxvkaV7axm+hFdNCM1HwKBgQDE" +
                      "drNGix7IqOC8+6Ix2hF+1gyI0l3E7cEDxoRaKrDdAvAipMA6iuseWecacawx7bI7" +
                      "k0fxFffKVitpUyON/a/cTjMbg43l5+/J+tVCTYHOA5dzqFYQ36MUd3LSTadWWskc" +
                      "zShVsv7jRg9mQjcWSPrKGuIZtY6XKVG7aMT428SC0QKBgQDawNe6yb6B+Bl/iS7Y" +
                      "tLl2Z4I8xWlkzCvClofMmzWNiOPCWehXf24iergVK4HUnelCVB0XQSDK4perAh8g" +
                      "IYR4hTuct+gYQhFtQCJvXcxeElHS7tElKYZq5QL1e5weTJ4wX+aOYqJA/V4lrmE+" +
                      "Nmo9sez/pKeLnCqra8Ew29paWg==";

            // Dump with
            // $ openssl rsa -in rsakey.pem -noout -text
            var modulus = "e5dca2d8528b5eb4114dbb3b824909142880bf4bb53517bce3cb613385ba914903e2e93b02a43cfe91a976f217" +
                          "1788f1f57b72a57de39b9aaa0af3f39474eb50cc1a9de44f1e8281814f730a80a6c9745a908c8ee1100117d44e" +
                          "12e1674cd308cb6da27cdcf135b22d497a21259411eb4a7bd5fd5833aeac7e8fdced854966c53a2b84f8f464f6" +
                          "b3f35abe645a41a2a1b0f365750fc6749a55bd5f7ab19d29975d7731d956cf05b29b238b0790bd4a3197a7bdca" +
                          "1f1ea3b3b2ef4aa9c3726323afce041a6f09dfc93befa777d2bb95a934a0cec52dfe1e23c3912c1c7fb66082c3" +
                          "9c19a6694c679b68357dc06f05b1433f321190c2326c6807210b747f2a16cf";
            var exponent = "010001";
            var d = "70c6917704f8b01c34a9288587e48179cc6d6e6d9c9851ef30ec25e27b680fc3fd0e2553f875d01f2e2430e19206cfff" +
                    "b66b3cd2893354b2cb5ed855d7ae8d8d74b6526523945a7f638c316b23b7b0fb4f3bc05a917da2aba8542ddb3d2d6a14" +
                    "d48a13c0a33e0d144037de9dc8ac1f268bc2ba38b43f9721b66eaafc35facf5a6286709fa37945c922a61227ff0f9e56" +
                    "6e2a157b34680e6043c36cf3c4097f3b3567dfb8556b19a72b34f9c3ab496261d072d8a514c94a610e8ef88512a61ca5" +
                    "c2c0fe3f75ecce9d409bd48919b22e0e2eb7356fb96aec0374be34023688cd77143684a68af133fdb31f214784788716" +
                    "3373e1e0f99a972f95772edd697d1821";
            var p = "faea2e8285b6049514688c3dbf181f7e8d8da140e7bc63c6fbe4bab64cdc8db41d70396af4134e006f64e2b6a5b44905" +
                    "59670500e2bd0cdff95e0310a3c357663659c2ea86c5822c41af7bcc84be36c73c466a6e3af3cee6f07a77cd1f565764" +
                    "49a8e524639f1645e439778651a7037624250c748a932456e5af39486cd0dcc7";
            var q = "ea8539d0dc42c09c9105ff87a63b62106478e4a9460f8d95273660f8ce2fd6e8f6266d1176b8bb3a945c321063643b71" +
                    "5c22bece4199e28a371344fc8214aca5940633443960e977b9197bcdd730f2cabf6a7d40960efeda79cf1f706dd695c9" +
                    "7ae074d8856a935034480a0f34074770a26619c189adc3f71b4ed9c34b081db9";
            var dp = "f006b7c94a69cdc663088427c9372561a5bdf7a52449b65532c022d0a38454d6195732c61a88a1148f7b3dd9a5786a6" +
                     "6009929532893dace233988cb112d9bdcfe5f2db3b68b183487fd7bfb307cd9e00bcbfca24828d5235ca67b16314522" +
                     "42a0a83dd36aad53dc362fb72439d5ffdcb344f1be4695edac66fa115d3423351f";
            var dq = "c476b3468b1ec8a8e0bcfba231da117ed60c88d25dc4edc103c6845a2ab0dd02f022a4c03a8aeb1e59e71a71ac31edb" +
                     "23b9347f115f7ca562b6953238dfdafdc4e331b838de5e7efc9fad5424d81ce039773a85610dfa3147772d24da7565a" +
                     "c91ccd2855b2fee3460f6642371648faca1ae219b58e972951bb68c4f8dbc482d1";
            var inverseQ = "dac0d7bac9be81f8197f892ed8b4b97667823cc56964cc2bc29687cc9b358d88e3c259e8577f6e227ab8152b8" +
                           "1d49de942541d174120cae297ab021f20218478853b9cb7e81842116d40226f5dcc5e1251d2eed12529866ae5" +
                           "02f57b9c1e4c9e305fe68e62a240fd5e25ae613e366a3db1ecffa4a78b9c2aab6bc130dbda5a5a";

            var rsa = Pem.ParsePrivateKeyPkcs8(key.Decode64());

            Assert.Equal(modulus.DecodeHex(), rsa.Modulus);
            Assert.Equal(exponent.DecodeHex(), rsa.Exponent);
            Assert.Equal(d.DecodeHex(), rsa.D);
            Assert.Equal(p.DecodeHex(), rsa.P);
            Assert.Equal(q.DecodeHex(), rsa.Q);
            Assert.Equal(dp.DecodeHex(), rsa.DP);
            Assert.Equal(dq.DecodeHex(), rsa.DQ);
            Assert.Equal(inverseQ.DecodeHex(), rsa.InverseQ);
        }
    }
}
