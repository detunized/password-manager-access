// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using FluentAssertions;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class SrpTest
    {
        [Fact]
        public void ParseModulus_parses_base64_url_encoded_string()
        {
            // Arrange
            var expected = Modulus.Decode64();

            // Act
            var modulus = Srp.ParseModulus(ModulusMessage);

            // Assert
            modulus.Should().Equal(expected);
        }

        [Theory]
        [InlineData("-----BEGIN PGP SIGNED MESSAGE-----", "?----BEGIN PGP SIGNED MESSAGE-----", "Invalid PGP message format: missing start *")]
        [InlineData("-----BEGIN PGP SIGNATURE-----", "?----BEGIN PGP SIGNATURE-----", "Invalid PGP message format: missing start *")]
        [InlineData("\n\n", "\n", "Invalid PGP message format: missing two *")]
        public void ParseModulus_throws_on_error(string replaceWhat, string replaceWith, string errorMessage)
        {
            // Arrange
            var brokenMessage = ModulusMessage.Replace(replaceWhat, replaceWith);

            // Act
            Action act = () => Srp.ParseModulus(brokenMessage);

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage(errorMessage);
        }

        // Test cases are generated using https://github.com/ProtonMail/go-srp
        [Theory]
        [InlineData(0, "password", "username", "QVBzxZXN/p8EHPIDOA0UjFi5s4f/OHNLYYDUXRYhAznMXlkJKRnS0eRM06JjNbz1gLX6KtTKEOrTcIP6Ue1o0Mop1daJRgvpbUQG+8NViAQcvgPF68t1801/w/J/q82dtZQzSIVGyqh8VXsItQNhmr7U1PEDK+hIJvjBqk33M7cjvz8LoNaCA4WIjb3y63Ysh0oeRPqeEItOPdAdsujNaDAH3hYBSEr1pS7ZZzIATCeHcznHoY/DspsDgElSyuEVllzWlaZNLRgAq9o7HqvP9V0n4rf507d8j2+rz84prTxJda7Tf8jnBKLpe7PIZI/7b1sawdTF9gFP1de+3WmSUw==")]
        [InlineData(0, "password", "uSeRnAmE", "QVBzxZXN/p8EHPIDOA0UjFi5s4f/OHNLYYDUXRYhAznMXlkJKRnS0eRM06JjNbz1gLX6KtTKEOrTcIP6Ue1o0Mop1daJRgvpbUQG+8NViAQcvgPF68t1801/w/J/q82dtZQzSIVGyqh8VXsItQNhmr7U1PEDK+hIJvjBqk33M7cjvz8LoNaCA4WIjb3y63Ysh0oeRPqeEItOPdAdsujNaDAH3hYBSEr1pS7ZZzIATCeHcznHoY/DspsDgElSyuEVllzWlaZNLRgAq9o7HqvP9V0n4rf507d8j2+rz84prTxJda7Tf8jnBKLpe7PIZI/7b1sawdTF9gFP1de+3WmSUw==")]
        [InlineData(1, "password", "username", "+oL95gPMxaUWeEPOy06xnc4TgkPokBXaVxSoAD7WsWInQL8xbMHrPiEZ2D0gJ2JWdZ7VR3RE/XvOCbOqjRhfcgGsasCh90ouRZXi1N1R6NI3cMcC7QwZuRSwwfDPg5rjlgFBb4K650TypRJhqmciS88ucV2XiJhfO+/Ugn5JpU46KozpapAe5rMBlZP59JA/Y30eSh9DC4m4giA1TX36Rn1L99V02dBs+lU8A8CjDD+dcUgeW5iDJE7gkHfG8jH+MULYtQReiJmkXxLPfRsmNy6nUUZ40dgiMV7bHyAXqZZ1C3e1Oz4L4lnLUcdowHQBgZmPwWvAyozro24ylOWSPw==")]
        [InlineData(1, "password", "uSeRnAmE", "+oL95gPMxaUWeEPOy06xnc4TgkPokBXaVxSoAD7WsWInQL8xbMHrPiEZ2D0gJ2JWdZ7VR3RE/XvOCbOqjRhfcgGsasCh90ouRZXi1N1R6NI3cMcC7QwZuRSwwfDPg5rjlgFBb4K650TypRJhqmciS88ucV2XiJhfO+/Ugn5JpU46KozpapAe5rMBlZP59JA/Y30eSh9DC4m4giA1TX36Rn1L99V02dBs+lU8A8CjDD+dcUgeW5iDJE7gkHfG8jH+MULYtQReiJmkXxLPfRsmNy6nUUZ40dgiMV7bHyAXqZZ1C3e1Oz4L4lnLUcdowHQBgZmPwWvAyozro24ylOWSPw==")]
        [InlineData(2, "password", "username", "+oL95gPMxaUWeEPOy06xnc4TgkPokBXaVxSoAD7WsWInQL8xbMHrPiEZ2D0gJ2JWdZ7VR3RE/XvOCbOqjRhfcgGsasCh90ouRZXi1N1R6NI3cMcC7QwZuRSwwfDPg5rjlgFBb4K650TypRJhqmciS88ucV2XiJhfO+/Ugn5JpU46KozpapAe5rMBlZP59JA/Y30eSh9DC4m4giA1TX36Rn1L99V02dBs+lU8A8CjDD+dcUgeW5iDJE7gkHfG8jH+MULYtQReiJmkXxLPfRsmNy6nUUZ40dgiMV7bHyAXqZZ1C3e1Oz4L4lnLUcdowHQBgZmPwWvAyozro24ylOWSPw==")]
        [InlineData(2, "password", "uSeRnAmE", "+oL95gPMxaUWeEPOy06xnc4TgkPokBXaVxSoAD7WsWInQL8xbMHrPiEZ2D0gJ2JWdZ7VR3RE/XvOCbOqjRhfcgGsasCh90ouRZXi1N1R6NI3cMcC7QwZuRSwwfDPg5rjlgFBb4K650TypRJhqmciS88ucV2XiJhfO+/Ugn5JpU46KozpapAe5rMBlZP59JA/Y30eSh9DC4m4giA1TX36Rn1L99V02dBs+lU8A8CjDD+dcUgeW5iDJE7gkHfG8jH+MULYtQReiJmkXxLPfRsmNy6nUUZ40dgiMV7bHyAXqZZ1C3e1Oz4L4lnLUcdowHQBgZmPwWvAyozro24ylOWSPw==")]
        [InlineData(2, "password", "--u.Se-Rn_AmE__.", "+oL95gPMxaUWeEPOy06xnc4TgkPokBXaVxSoAD7WsWInQL8xbMHrPiEZ2D0gJ2JWdZ7VR3RE/XvOCbOqjRhfcgGsasCh90ouRZXi1N1R6NI3cMcC7QwZuRSwwfDPg5rjlgFBb4K650TypRJhqmciS88ucV2XiJhfO+/Ugn5JpU46KozpapAe5rMBlZP59JA/Y30eSh9DC4m4giA1TX36Rn1L99V02dBs+lU8A8CjDD+dcUgeW5iDJE7gkHfG8jH+MULYtQReiJmkXxLPfRsmNy6nUUZ40dgiMV7bHyAXqZZ1C3e1Oz4L4lnLUcdowHQBgZmPwWvAyozro24ylOWSPw==")]
        [InlineData(3, "password", "username", "+hUoDyOSCTsuCTbPuEi44SrgzklYClF5QeXsZQTpnWtrYN26zLrOilsl8vJO8QTu9FCxaSsgexg2fN4S7ktJLoZ5nAgvCdh22Hcpv1C4N64uZxgi1NmLztxaeXRIEhqyEpVpcr42lGLexibvkYIFdYdARigRXwi4Mg0mvOBBDadCZGpQGMbZ13RKbPjU7SUdugMQW5OCBMia0MK1+6FqWDq02iBQ86cPSjFV1pI5hoziV3pZkmPXuSJGVAp7RvjXLCxW5g6m9qwKqJaKbKJZ9ZaGFnvi99h47Rp7JjECpvg42hvvaB/YNLWH2Qtqcn9yGHiC6E/eUxGGt2gl1B2dMA==")]
        [InlineData(4, "password", "username", "+hUoDyOSCTsuCTbPuEi44SrgzklYClF5QeXsZQTpnWtrYN26zLrOilsl8vJO8QTu9FCxaSsgexg2fN4S7ktJLoZ5nAgvCdh22Hcpv1C4N64uZxgi1NmLztxaeXRIEhqyEpVpcr42lGLexibvkYIFdYdARigRXwi4Mg0mvOBBDadCZGpQGMbZ13RKbPjU7SUdugMQW5OCBMia0MK1+6FqWDq02iBQ86cPSjFV1pI5hoziV3pZkmPXuSJGVAp7RvjXLCxW5g6m9qwKqJaKbKJZ9ZaGFnvi99h47Rp7JjECpvg42hvvaB/YNLWH2Qtqcn9yGHiC6E/eUxGGt2gl1B2dMA==")]
        public void HashPassword_returns_a_hashed_password(int version, string password, string username, string expected)
        {
            // Arrange
            var expectedBytes = expected.Decode64();
            var salt = "salt!salt!".ToBytes();

            var modulus = new byte[256];
            for (var i = 0; i < 256; i++)
                modulus[i] = (byte)i;

            // Act
            var hash = Srp.HashPassword(version, password, username, salt, modulus);

            // Assert
            hash.Should().Equal(expectedBytes);
        }

        //
        // Data
        //

        private const string Modulus =
            "A5AwfkcWr2Sq7Wy8hpOHAnAFo8hZdKsVmInqvOckcHaeV36YPTK4H7yfE5cUtkHaL/MaPl1J5expZ9x/mXkAjsTicSXEi3iAAaBa4CrW" +
            "Yydjm29ESeejdwwsR9M/FprqvYkJ1Nb6VzhKr2ZvjPKiw2UK1N0PcuYlf+0fxOXOH0vW0aXBk0nKu1vlloqTVoYUkdevAs1eL2bCjS0d" +
            "gECy2QxqNdNj9/uhDVshxEJxl1wyAPvLG0Eq7XWmRGyA3pgEDp3IwhTVQJ+BfawJf+vN/Q4tEOtTAhCFCCpL59bFw5fTehKrMJ6cfAfd" +
            "QIrqiVygbW5FRevLqQVX/YlIYghn0g==";

        private const string ModulusMessage =
            "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA256\n" +
            "\n" +
            Modulus + "\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: ProtonMail\n" +
            "Comment: https://protonmail.com\n" +
            "\n" +
            "wl4EARYIABAFAlwB1jwJEDUFhcTpUY8mAABhWgEAypod4Gzxqy1RoZhVMG5a\n" +
            "Tnbwx8xwdYwmvqq7cPHKBrYA/0+eOtSjHOA95MjC8aq1v5XOsHhbxnnSvPGJ\n" +
            "Z/+kS6gI\n" +
            "=ARO0\n" +
            "-----END PGP SIGNATURE-----\n";
    }
}
