// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Numerics;
using FluentAssertions;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass;
using Xunit;

namespace PasswordManagerAccess.Test.ProtonPass
{
    public class SrpTest
    {
        // Test cases are generated using https://github.com/ProtonMail/go-srp
        [Fact]
        public void GenerateProofs_returns_proofs()
        {
            // Arrange
            var serverEphemeralBytes = ServerEphemeral.Decode64();
            var modulus = Modulus.Decode64();
            var hashPassword = Srp.HashPassword(0, "password", "username", Array.Empty<byte>(), modulus);

            var expectedClientEphemeral =
                ("kLP+/2h0p+uQGz59GtpPlRFemMa0H6H0DiRLCveLc4RIzlZt+PcmlVBanNdV5wvK6JWdjuoKCK1Zo0IZcYVGAKWbbMOkEmTha1m" +
                 "DGH2nvOu6Tp5T5PytI+ohRN8xD3wzAY9vg/kjO8cZc8t5GKncfHar1go2P5I0ipEZ0Yc4QlKb8GMq0j4o2o/FLrZUen6dzdspmR" +
                 "xq7iKNP3vCg/C/N6wUyrcUse5zsCA4oStlfatDYqsmJGZwBbLrq7++9kESnGFYlKpUnk6McEDmMm4w8nZWDMOUFTKPjj2DbgR4U" +
                 "el/Q7+phz3ph+605Rx6LxWqZJXs2n5u50iskPSSw4aeiw==").Decode64();

            var expectedClientProof =
                ("NxvhCQi7O1YsqJH6qK8z7Ofvak+iDBoMZLK7RQ6apiYtQ92k0LK/tsKUVB1hBzKNPc3AtANZWgZmClZ6EwX3HURmsCZ5IItuTG/" +
                 "Doxt2uGwQVXcIF/jIQRf/CXbySci0ZUrgAKsbOFKb1hZImQFXjDHgwouDfnQv/vpDucY54C8M1KLrsFkijWrxtKOJyqPy0C5BYr" +
                 "YOTmPpOOLdAnQ+79VxInhWBYL7+Pbzf8SYC9RWKuO2nKjZqPHURYnM+YE5ieiI0oReI+/IbgsTbnZvjQ1EYgJT7e9dfYTF7hSvo" +
                 "xPzZzSi1Dvr73g8YchIxEugqOOSQ/tM6SnVwvKbWKQyiA==").Decode64();

            var expectedServerProof =
                ("8ntsxOyL95QBgCi1yj+KRFYXF+Nx93y0h6zQRKFb/tem85a+lCm4EZTJsUUBH+qxz41oisrpr3afa6PuzSOmCHms1iugv3bQzSV" +
                 "X/BMKZl6Iq7vJG2GiHSvXkmo1CdGKQgoNbsw4c4RZCJfRQ1TVeL2aekErGx+gsyQ9r3sApARhcoz1hverRIB8bIzb+goJj5rLS/" +
                 "cx6Ce6lKZKt3kcSarEIFzO5cuKyj+sqF5SW/yH1pwEsF+RDPPIcOGbtprbujm3VHzawY678ufCpPDNsgp7BPX8cB2EOxn+/22ig" +
                 "G9hZqDm7DFQi/1u/NY4BGMzQCIMNb92khCsUkioHuqg7A==").Decode64();

            // Need to supply a "random" number or the tests will fail
            BigInteger GetRandomBigInt(BigInteger min, BigInteger max)
            {
                return BigInteger.Parse(
                    "105470616520292742113796707158374971919237113921001814738018539058088099151969076072037119025817" +
                    "025309092299131390290642000536535453569561803785071242711094590131126040239289433612227116128028" +
                    "805349993386278410760127857080891258890968456587363742272616744158895304082261290072729719945715" +
                    "737117999787687229057403553386563956741397002904180141195436141164475790436201393962812827253064" +
                    "294812283952343066489492827921449224134654166270552984438424061767821739424805349057494074140637" +
                    "786202712971068138429500248316356726979554318393344595633669068348422081621361182199116750832205" +
                    "20501587197458892001573436641639539315377");
            }

            // Act
            var proofs = Srp.GenerateProofs(Srp.BitLength,
                                            serverEphemeralBytes,
                                            modulus,
                                            hashPassword,
                                            GetRandomBigInt);

            // Assert
            proofs.Should().NotBeNull();
            proofs.ClientEphemeral.Should().Equal(expectedClientEphemeral);
            proofs.ClientProof.Should().Equal(expectedClientProof);
            proofs.ServerProof.Should().Equal(expectedServerProof);
        }

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

        // Test cases are generated using https://github.com/ProtonMail/go-srp
        [Theory]
        [InlineData("PTTsDBs/mlLnSk6VmtFghe", "$2y$10$PTTsDBs/mlLnSk6VmtFgheNSiK/lSwtJsrBLLDK3kZYI7193nInqy")]
        [InlineData("4DZHd6WZX4fEaWKtCfYdde", "$2y$10$4DZHd6WZX4fEaWKtCfYddeZfcryISo9eEMgbA90O.Wnnz1s1VKmKC")]
        [InlineData("RpyeXO7K2eD3r/ZZ/B63V.", "$2y$10$RpyeXO7K2eD3r/ZZ/B63V.Tya53OExbyO8LR7TB93KYP4PvC.EPMW")]
        [InlineData("xVEeHQI8CyNkblUJDhyx3u", "$2y$10$xVEeHQI8CyNkblUJDhyx3uZjo8GDXoNNVoRpLwLvssO1GvV3eYFJS")]
        [InlineData("d4Q1rrFYjGq2jyVUi7YwTu", "$2y$10$d4Q1rrFYjGq2jyVUi7YwTuikgSeAgJfaAYJSJZIbIOvW1GBFwx2J6")]
        [InlineData("0D/DzrAPBFW/31/wZ1PtZe", "$2y$10$0D/DzrAPBFW/31/wZ1PtZe.tC/Vs7zCCjFXlp2Fm.FmWJWjeWp8Ei")]
        [InlineData("gufBPy/8yOKCV1/wZ1PtZe", "$2y$10$gufBPy/8yOKCV1/wZ1PtZeiqMTbeEBhIWbMeesVsXPNeHqavzTVbC")]
        [InlineData("nWTS2dUGqrnsZ1/wZ1PtZe", "$2y$10$nWTS2dUGqrnsZ1/wZ1PtZeS1JKRo937PFwxDcAcWK/3cT/lgCkNYC")]
        [InlineData("KIlx2Lazv8vP0l/wZ1PtZe", "$2y$10$KIlx2Lazv8vP0l/wZ1PtZeowDtmWBAHrX9G/eQNSur1BLGNrGJTfi")]
        [InlineData("KjCAeXQCz7COsl/wZ1PtZe", "$2y$10$KjCAeXQCz7COsl/wZ1PtZeUE7xw996C7yWkAl5t.zaJL2K46RFTdm")]
        public void BCryptHashPassword_returns_a_hashed_password(string salt, string expected)
        {
            // Act
            var hash = Srp.BCryptHashPassword("test!!!", salt);

            // Assert
            hash.Should().Be(expected);
        }

        // Test cases are generated using https://github.com/ProtonMail/go-srp
        [Theory]
        [InlineData("49c093906a4d417bb44b371bb003bd91", "$2y$10$49c093906a4d417bb44b37zRXXeHEMZPzRkBEWery9ONa5fugEy92")]
        [InlineData("f9196525572774ab1e7e60526a413824", "$2y$10$f9196525572774ab1e7e601WV6Ab0E3Dy7q2VMj0D5fU/Dv6z9uA.")]
        [InlineData("685fa6db4217fb5373dfe1c12e5271ec", "$2y$10$685fa6db4217fb5373dfe1d8qAq3TPbilfpKOScuarPX4pzh0RVWC")]
        [InlineData("7f36566abd3982546f72e76cfba33769", "$2y$10$7f36566abd3982546f72e7gqhbLBGQ4EPm8zkEdeocCt6kdwh1/76")]
        [InlineData("04cbb9de8bec512ad6703ad92643ecb4", "$2y$10$04cbb9de8bec512ad6703a/uC11RORG/AaYz7b2D4jbDzA.xB4kQ6")]
        [InlineData("e9079a267596a00c7efaa49041444765", "$2y$10$e9079a267596a00c7efaa4pLrFZY5nkDOQABkgP8P5mODpud2tGqC")]
        [InlineData("9f8df46d3ed1f2d1623a166dbbd0bab4", "$2y$10$9f8df46d3ed1f2d1623a16psEpX6df1LNDpPDZK.HQzOXc8e7sZUG")]
        [InlineData("8613e2cb16196240312d6a557c763d71", "$2y$10$8613e2cb16196240312d6arbNDxBgRep62Hf395yqCrXtmly5sqYm")]
        [InlineData("396497456b74c3f1eaea8a66e97d0793", "$2y$10$396497456b74c3f1eaea8aJxP9RU/Rhbo.UwLXz5BXDz6TftJtCj2")]
        [InlineData("c91fc38a3e520ed9af193027731ae4e6", "$2y$10$c91fc38a3e520ed9af1930tYZQdVi9V6y/O3Ul7I.x2Ql8LS5hL/6")]
        public void FixBCryptHash_fixes_broken_hash(string salt, string expected)
        {
            // Arrange
            var broken = Srp.BCryptHashPassword("test!!!", salt);

            // Act
            var hash = Srp.FixBCryptHash(broken, salt);

            // Assert
            hash.Should().Be(expected);
            hash.Should().NotBe(broken);
        }

        // Test cases are generated using https://github.com/ProtonMail/go-srp
        [Theory]
        [InlineData("6e", "Ze")]
        [InlineData("2e86", "JmW")]
        [InlineData("3e0dbb", "Ne05")]
        [InlineData("512673fc", "SQXx9.")]
        [InlineData("a56f061562", "nU6EDUG")]
        [InlineData("216266b840df", "GUHksCBd")]
        [InlineData("d90bfaeb8d03a5", "0Ot442yBnO")]
        [InlineData("309ac265dfc86ef0", "KHpAXb9GZt.")]
        [InlineData("0853d851e0f8f917a3", "ADNWScB28Pch")]
        public void EncodeBase64_returns_bcrypt_base64(string inputHex, string expected)
        {
            // Arrange
            var input = inputHex.DecodeHex();

            // Act
            var output = Srp.EncodeBase64(input, input.Length);

            // Assert
            output.Should().Be(expected);
        }

        [Theory]
        [InlineData("", "", "")]
        [InlineData("", "DEADBEEF", "DEADBEEF")]
        [InlineData("DEADBEEF", "", "DEADBEEF")]
        [InlineData("DEAD", "BEEF", "DEADBEEF")]
        [InlineData("DEADBEEF", "BADC0FFE", "DEADBEEFBADC0FFE")]
        public void Concat2_returns_concatenated_arrays(string aHex, string bHex, string expectedHex)
        {
            // Arrange
            var a = aHex.DecodeHex();
            var b = bHex.DecodeHex();
            var expected = expectedHex.DecodeHex();

            // Act
            var result = Srp.Concat(a, b);

            // Assert
            result.Should().Equal(expected);
        }

        [Theory]
        [InlineData("", "", "", "")]
        [InlineData("DEADBEEF", "", "", "DEADBEEF")]
        [InlineData("", "DEADBEEF", "", "DEADBEEF")]
        [InlineData("", "", "DEADBEEF", "DEADBEEF")]
        [InlineData("", "DEAD", "BEEF", "DEADBEEF")]
        [InlineData("DEAD", "", "BEEF", "DEADBEEF")]
        [InlineData("DEAD", "BEEF", "", "DEADBEEF")]
        [InlineData("DEAD", "BEEF", "BADC0FFE", "DEADBEEFBADC0FFE")]
        public void Concat3_returns_concatenated_arrays(string aHex, string bHex, string cHex, string expectedHex)
        {
            // Arrange
            var a = aHex.DecodeHex();
            var b = bHex.DecodeHex();
            var c = cHex.DecodeHex();
            var expected = expectedHex.DecodeHex();

            // Act
            var result = Srp.Concat(a, b, c);

            // Assert
            result.Should().Equal(expected);
        }

        //
        // Data
        //

        private const string ServerEphemeral =
            "M099L/yzzNqcgzcmm71Rl+ibyBRmyaMAk4JvOC3wJmkR0OnzsN6mECmbci2yV3mJHpIZyKJy3iaoUjOGJF4Bb/KUThk4x3IsP+PY+RFJ" +
            "3d/fNOvBygdRqjr4liR+gnn+vWEgDW9CDClY4Bg6X9hx0JDV7RjYXqKBVWCT4+Tg+F0dv7XmZnbFygqJcSigBM7M5ZMI2IgFVkKWdwvm" +
            "rhoMsxFbtV7NeSJ17+8Q7TlMt+L1/DiddReN1Gtuu8KBpS5whXGqPkg/gU7H+oUagQbCtkzIOjgmmyInwMKUohI/jdPPd1i7mtO1Yj6+" +
            "hJVLVHkJkn+GCV6iWed0KvTbdSC9hA==";

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
