// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void DeriveKey_returns_derived_key()
        {
            var key = Crypto.DeriveKey(Username, Password, 100);
            Assert.That(key, Is.EqualTo(DerivedKey.Decode64()));
        }

        [Test]
        public void DeriveKey_trims_whitespace_and_lowercases_username()
        {
            var key = Crypto.DeriveKey(" UsErNaMe ", Password, 100);
            Assert.That(key, Is.EqualTo(DerivedKey.Decode64()));
        }

        [Test]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Crypto.HashPassword(Password, DerivedKey.Decode64());
            Assert.That(hash, Is.EqualTo(PasswordHash.Decode64()));
        }

        [Test]
        public void Hmac256_bytes_returns_hashed_message()
        {
            Assert.That(Crypto.Hmac("salt".ToBytes(), "message".ToBytes()),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        [Test]
        public void HkdfExpand_returns_expected_result()
        {
            Assert.That(Crypto.HkdfExpand("prk".ToBytes(), "info".ToBytes()),
                        Is.EqualTo("t+eNA48Gl56FVhjNqTxs9cktUhG28eg3i/Rbf0QtPSU=".Decode64()));
        }

        [Test]
        public void ExpandKey_expands_key_to_64_bytes()
        {
            var expected = "GKPlyJlfe4rO+RNeBj6P4Jm1Ds4QFB23rN2WvwVcb5Iw0U+9uVf7jwQ04Yq75uCrOSsL7HonzBzNdYi1hO/mlQ==";
            Assert.That(Crypto.ExpandKey("key".ToBytes()), Is.EqualTo(expected.Decode64()));
        }

        [Test]
        public void DecryptAes256_decrypts_ciphertext()
        {
            Assert.That(
                Crypto.DecryptAes256("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                     "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                     "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64()),
                Is.EqualTo("All your base are belong to us".ToBytes()));
        }

        [Test]
        public void DecryptAes256_throws_on_incorrect_encryption_key()
        {
            Assert.That(() => Crypto.DecryptAes256("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                                   "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                                   "Incorrect key must be 32 bytes!!".ToBytes()),
                        Throws
                            .InstanceOf<ClientException>()
                            .And.Property("Reason").EqualTo(ClientException.FailureReason.CryptoError)
                            .And.Message.EqualTo("AES decryption failed")
                            .And.InnerException.InstanceOf<CryptographicException>());
        }

        [Test]
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

            // Check nothing here. Not throwing anything is good enough.
            Crypto.ParsePrivateKeyPkcs8(key.Decode64());
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string DerivedKey = "antk7JoUPTHk37mhIHNXg5kUM1pNaf1p+JR8XxtDzg4=";
        private const string PasswordHash = "zhQ5ps7B3qN3/m2JVn+UckMTPH5dOI6K369pCiLL9wQ=";
    }
}
