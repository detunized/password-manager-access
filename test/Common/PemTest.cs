// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class PemTest: TestBase
    {
        [Fact]
        public void ParsePrivateKeyPkcs8_parses_openssl_generated_key_pem_file()
        {
            var pem = GetFixture("openssl-private-key", "pem");
            var rsa = Pem.ParsePrivateKeyPkcs8(pem);
            VerifyRsaKey(rsa);
        }

        [Fact]
        public void ParsePrivateKeyPkcs8_parses_openssl_generated_key()
        {
            var rsa = Pem.ParsePrivateKeyPkcs8(PrivateKeyPkcs8);
            VerifyRsaKey(rsa);
        }

        [Fact]
        public void ParsePrivateKeyPkcs1_parses_openssl_generated_key()
        {
            var rsa = Pem.ParseRsaPrivateKeyPkcs1(PrivateKeyPkcs1);
            VerifyRsaKey(rsa);
        }

        //
        // Helpers
        //

        private static void VerifyRsaKey(RSAParameters rsa)
        {
            Assert.Equal(PrivateKeyModulus, rsa.Modulus);
            Assert.Equal(PrivateKeyExponent, rsa.Exponent);
            Assert.Equal(PrivateKeyD, rsa.D);
            Assert.Equal(PrivateKeyP, rsa.P);
            Assert.Equal(PrivateKeyQ, rsa.Q);
            Assert.Equal(PrivateKeyDp, rsa.DP);
            Assert.Equal(PrivateKeyDq, rsa.DQ);
            Assert.Equal(PrivateKeyInverseQ, rsa.InverseQ);
        }

        //
        // Data
        //

        // The entire PKCS#8 PrivateKeyInfo. Generated with:
        // $ openssl genpkey -out rsakey.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
        private const string PrivateKeyPkcs8Base64 =
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDl3KLYUotetBFNuzuCSQkUKIC/S7U1F7zjy2EzhbqRSQPi6TsCpDz+" +
            "kal28hcXiPH1e3KlfeObmqoK8/OUdOtQzBqd5E8egoGBT3MKgKbJdFqQjI7hEAEX1E4S4WdM0wjLbaJ83PE1si1JeiEllBHrSnvV/Vgz" +
            "rqx+j9zthUlmxTorhPj0ZPaz81q+ZFpBoqGw82V1D8Z0mlW9X3qxnSmXXXcx2VbPBbKbI4sHkL1KMZenvcofHqOzsu9KqcNyYyOvzgQa" +
            "bwnfyTvvp3fSu5WpNKDOxS3+HiPDkSwcf7ZggsOcGaZpTGebaDV9wG8FsUM/MhGQwjJsaAchC3R/KhbPAgMBAAECggEAcMaRdwT4sBw0" +
            "qSiFh+SBecxtbm2cmFHvMOwl4ntoD8P9DiVT+HXQHy4kMOGSBs//tms80okzVLLLXthV166NjXS2UmUjlFp/Y4wxayO3sPtPO8BakX2i" +
            "q6hULds9LWoU1IoTwKM+DRRAN96dyKwfJovCuji0P5chtm6q/DX6z1pihnCfo3lFySKmEif/D55WbioVezRoDmBDw2zzxAl/OzVn37hV" +
            "axmnKzT5w6tJYmHQctilFMlKYQ6O+IUSphylwsD+P3Xszp1Am9SJGbIuDi63NW+5auwDdL40AjaIzXcUNoSmivEz/bMfIUeEeIcWM3Ph" +
            "4Pmaly+Vdy7daX0YIQKBgQD66i6ChbYElRRojD2/GB9+jY2hQOe8Y8b75Lq2TNyNtB1wOWr0E04Ab2TitqW0SQVZZwUA4r0M3/leAxCj" +
            "w1dmNlnC6obFgixBr3vMhL42xzxGam46887m8Hp3zR9WV2RJqOUkY58WReQ5d4ZRpwN2JCUMdIqTJFblrzlIbNDcxwKBgQDqhTnQ3ELA" +
            "nJEF/4emO2IQZHjkqUYPjZUnNmD4zi/W6PYmbRF2uLs6lFwyEGNkO3FcIr7OQZniijcTRPyCFKyllAYzRDlg6Xe5GXvN1zDyyr9qfUCW" +
            "Dv7aec8fcG3Wlcl64HTYhWqTUDRICg80B0dwomYZwYmtw/cbTtnDSwgduQKBgQDwBrfJSmnNxmMIhCfJNyVhpb33pSRJtlUywCLQo4RU" +
            "1hlXMsYaiKEUj3s92aV4amYAmSlTKJPaziM5iMsRLZvc/l8ts7aLGDSH/Xv7MHzZ4AvL/KJIKNUjXKZ7FjFFIkKgqD3Taq1T3DYvtyQ5" +
            "1f/cs0TxvkaV7axm+hFdNCM1HwKBgQDEdrNGix7IqOC8+6Ix2hF+1gyI0l3E7cEDxoRaKrDdAvAipMA6iuseWecacawx7bI7k0fxFffK" +
            "VitpUyON/a/cTjMbg43l5+/J+tVCTYHOA5dzqFYQ36MUd3LSTadWWskczShVsv7jRg9mQjcWSPrKGuIZtY6XKVG7aMT428SC0QKBgQDa" +
            "wNe6yb6B+Bl/iS7YtLl2Z4I8xWlkzCvClofMmzWNiOPCWehXf24iergVK4HUnelCVB0XQSDK4perAh8gIYR4hTuct+gYQhFtQCJvXcxe" +
            "ElHS7tElKYZq5QL1e5weTJ4wX+aOYqJA/V4lrmE+Nmo9sez/pKeLnCqra8Ew29paWg==";

        // The same key as above but just the RSAPrivateKey part of the PKCS#8 PrivateKeyInfo. Could be generated with:
        // $ openssl genrsa -f4 -out rsakey.pem 2048
        private const string PrivateKeyPkcs1Base64 =
            "MIIEpQIBAAKCAQEA5dyi2FKLXrQRTbs7gkkJFCiAv0u1NRe848thM4W6kUkD4uk7AqQ8/pGpdvIXF4jx9XtypX3jm5qqCvPzlHTrUMwa" +
            "neRPHoKBgU9zCoCmyXRakIyO4RABF9ROEuFnTNMIy22ifNzxNbItSXohJZQR60p71f1YM66sfo/c7YVJZsU6K4T49GT2s/NavmRaQaKh" +
            "sPNldQ/GdJpVvV96sZ0pl113MdlWzwWymyOLB5C9SjGXp73KHx6js7LvSqnDcmMjr84EGm8J38k776d30ruVqTSgzsUt/h4jw5EsHH+2" +
            "YILDnBmmaUxnm2g1fcBvBbFDPzIRkMIybGgHIQt0fyoWzwIDAQABAoIBAHDGkXcE+LAcNKkohYfkgXnMbW5tnJhR7zDsJeJ7aA/D/Q4l" +
            "U/h10B8uJDDhkgbP/7ZrPNKJM1Syy17YVdeujY10tlJlI5Raf2OMMWsjt7D7TzvAWpF9oquoVC3bPS1qFNSKE8CjPg0UQDfencisHyaL" +
            "wro4tD+XIbZuqvw1+s9aYoZwn6N5RckiphIn/w+eVm4qFXs0aA5gQ8Ns88QJfzs1Z9+4VWsZpys0+cOrSWJh0HLYpRTJSmEOjviFEqYc" +
            "pcLA/j917M6dQJvUiRmyLg4utzVvuWrsA3S+NAI2iM13FDaEporxM/2zHyFHhHiHFjNz4eD5mpcvlXcu3Wl9GCECgYEA+uougoW2BJUU" +
            "aIw9vxgffo2NoUDnvGPG++S6tkzcjbQdcDlq9BNOAG9k4raltEkFWWcFAOK9DN/5XgMQo8NXZjZZwuqGxYIsQa97zIS+Nsc8RmpuOvPO" +
            "5vB6d80fVldkSajlJGOfFkXkOXeGUacDdiQlDHSKkyRW5a85SGzQ3McCgYEA6oU50NxCwJyRBf+HpjtiEGR45KlGD42VJzZg+M4v1uj2" +
            "Jm0Rdri7OpRcMhBjZDtxXCK+zkGZ4oo3E0T8ghSspZQGM0Q5YOl3uRl7zdcw8sq/an1Alg7+2nnPH3Bt1pXJeuB02IVqk1A0SAoPNAdH" +
            "cKJmGcGJrcP3G07Zw0sIHbkCgYEA8Aa3yUppzcZjCIQnyTclYaW996UkSbZVMsAi0KOEVNYZVzLGGoihFI97PdmleGpmAJkpUyiT2s4j" +
            "OYjLES2b3P5fLbO2ixg0h/17+zB82eALy/yiSCjVI1ymexYxRSJCoKg902qtU9w2L7ckOdX/3LNE8b5Gle2sZvoRXTQjNR8CgYEAxHaz" +
            "RoseyKjgvPuiMdoRftYMiNJdxO3BA8aEWiqw3QLwIqTAOorrHlnnGnGsMe2yO5NH8RX3ylYraVMjjf2v3E4zG4ON5efvyfrVQk2BzgOX" +
            "c6hWEN+jFHdy0k2nVlrJHM0oVbL+40YPZkI3Fkj6yhriGbWOlylRu2jE+NvEgtECgYEA2sDXusm+gfgZf4ku2LS5dmeCPMVpZMwrwpaH" +
            "zJs1jYjjwlnoV39uInq4FSuB1J3pQlQdF0EgyuKXqwIfICGEeIU7nLfoGEIRbUAib13MXhJR0u7RJSmGauUC9XucHkyeMF/mjmKiQP1e" +
            "Ja5hPjZqPbHs/6Sni5wqq2vBMNvaWlo=";

        // Dumped with
        // $ openssl rsa -in rsakey.pem -noout -text
        private const string PrivateKeyModulusHex =
            "e5dca2d8528b5eb4114dbb3b824909142880bf4bb53517bce3cb613385ba914903e2e93b02a43cfe91a976f2171788f1f57b72a5" +
            "7de39b9aaa0af3f39474eb50cc1a9de44f1e8281814f730a80a6c9745a908c8ee1100117d44e12e1674cd308cb6da27cdcf135b2" +
            "2d497a21259411eb4a7bd5fd5833aeac7e8fdced854966c53a2b84f8f464f6b3f35abe645a41a2a1b0f365750fc6749a55bd5f7a" +
            "b19d29975d7731d956cf05b29b238b0790bd4a3197a7bdca1f1ea3b3b2ef4aa9c3726323afce041a6f09dfc93befa777d2bb95a9" +
            "34a0cec52dfe1e23c3912c1c7fb66082c39c19a6694c679b68357dc06f05b1433f321190c2326c6807210b747f2a16cf";

        private const string PrivateKeyExponentHex = "010001";

        private const string PrivateKeyDHex =
            "70c6917704f8b01c34a9288587e48179cc6d6e6d9c9851ef30ec25e27b680fc3fd0e2553f875d01f2e2430e19206cfffb66b3cd2" +
            "893354b2cb5ed855d7ae8d8d74b6526523945a7f638c316b23b7b0fb4f3bc05a917da2aba8542ddb3d2d6a14d48a13c0a33e0d14" +
            "4037de9dc8ac1f268bc2ba38b43f9721b66eaafc35facf5a6286709fa37945c922a61227ff0f9e566e2a157b34680e6043c36cf3" +
            "c4097f3b3567dfb8556b19a72b34f9c3ab496261d072d8a514c94a610e8ef88512a61ca5c2c0fe3f75ecce9d409bd48919b22e0e" +
            "2eb7356fb96aec0374be34023688cd77143684a68af133fdb31f2147847887163373e1e0f99a972f95772edd697d1821";

        private const string PrivateKeyPHex =
            "faea2e8285b6049514688c3dbf181f7e8d8da140e7bc63c6fbe4bab64cdc8db41d70396af4134e006f64e2b6a5b4490559670500" +
            "e2bd0cdff95e0310a3c357663659c2ea86c5822c41af7bcc84be36c73c466a6e3af3cee6f07a77cd1f56576449a8e524639f1645" +
            "e439778651a7037624250c748a932456e5af39486cd0dcc7";

        private const string PrivateKeyQHex =
            "ea8539d0dc42c09c9105ff87a63b62106478e4a9460f8d95273660f8ce2fd6e8f6266d1176b8bb3a945c321063643b715c22bece" +
            "4199e28a371344fc8214aca5940633443960e977b9197bcdd730f2cabf6a7d40960efeda79cf1f706dd695c97ae074d8856a9350" +
            "34480a0f34074770a26619c189adc3f71b4ed9c34b081db9";

        private const string PrivateKeyDpHex =
            "f006b7c94a69cdc663088427c9372561a5bdf7a52449b65532c022d0a38454d6195732c61a88a1148f7b3dd9a5786a6600992953" +
            "2893dace233988cb112d9bdcfe5f2db3b68b183487fd7bfb307cd9e00bcbfca24828d5235ca67b1631452242a0a83dd36aad53dc" +
            "362fb72439d5ffdcb344f1be4695edac66fa115d3423351f";

        private const string PrivateKeyDqHex =
            "c476b3468b1ec8a8e0bcfba231da117ed60c88d25dc4edc103c6845a2ab0dd02f022a4c03a8aeb1e59e71a71ac31edb23b9347f1" +
            "15f7ca562b6953238dfdafdc4e331b838de5e7efc9fad5424d81ce039773a85610dfa3147772d24da7565ac91ccd2855b2fee346" +
            "0f6642371648faca1ae219b58e972951bb68c4f8dbc482d1";

        private const string PrivateKeyInverseQHex =
            "dac0d7bac9be81f8197f892ed8b4b97667823cc56964cc2bc29687cc9b358d88e3c259e8577f6e227ab8152b81d49de942541d17" +
            "4120cae297ab021f20218478853b9cb7e81842116d40226f5dcc5e1251d2eed12529866ae502f57b9c1e4c9e305fe68e62a240fd" +
            "5e25ae613e366a3db1ecffa4a78b9c2aab6bc130dbda5a5a";

        private static readonly byte[] PrivateKeyPkcs8 = PrivateKeyPkcs8Base64.Decode64();
        private static readonly byte[] PrivateKeyPkcs1 = PrivateKeyPkcs1Base64.Decode64();

        private static readonly byte[] PrivateKeyModulus = PrivateKeyModulusHex.DecodeHex();
        private static readonly byte[] PrivateKeyExponent = PrivateKeyExponentHex.DecodeHex();
        private static readonly byte[] PrivateKeyD = PrivateKeyDHex.DecodeHex();
        private static readonly byte[] PrivateKeyP = PrivateKeyPHex.DecodeHex();
        private static readonly byte[] PrivateKeyQ = PrivateKeyQHex.DecodeHex();
        private static readonly byte[] PrivateKeyDp = PrivateKeyDpHex.DecodeHex();
        private static readonly byte[] PrivateKeyDq = PrivateKeyDqHex.DecodeHex();
        private static readonly byte[] PrivateKeyInverseQ = PrivateKeyInverseQHex.DecodeHex();
    }
}
