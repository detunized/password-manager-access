// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test.Common
{
    public static class CryptoTestVectors
    {
        //
        // Poly1305
        //

        public struct Poly1305TestVector
        {
            public byte[] Key => KeyHex.DecodeHex();
            public byte[] Tag => TagHex.DecodeHex();
            public byte[] Input => InputHex.DecodeHex();

            internal string KeyHex;
            internal string TagHex;
            internal string InputHex;
        }

        public static readonly Poly1305TestVector[] Poly1305TestVectors =
        {
            // edge cases
            new Poly1305TestVector
            {
                // see https://go-review.googlesource.com/#/c/30101/
                KeyHex = "3b3a29e93b213a5c5c3b3b053a3a8c0d00000000000000000000000000000000",
                TagHex = "6dc18b8c344cd79927118bbe84b7f314",
                InputHex = "81d8b2e46a25213b58fee4213a2a28e921c12a9632516d3b73272727becf2129",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "04000000000000000000000000000000", // (2^130-1) % (2^130-5)
                InputHex = "ffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000" +
                           "0000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "faffffffffffffffffffffffffffffff", // (2^130-6) % (2^130-5)
                InputHex = "faffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000" +
                           "0000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (2^130-5) % (2^130-5)
                InputHex = "fbffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000" +
                           "0000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "f9ffffffffffffffffffffffffffffff", // (2*(2^130-6)) % (2^130-5)
                InputHex = "fafffffffffffffffffffffffffffffffaffffffffffffffffffffffffffffff0000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (2*(2^130-5)) % (2^130-5)
                InputHex = "fbfffffffffffffffffffffffffffffffbffffffffffffffffffffffffffffff0000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "f8ffffffffffffffffffffffffffffff", // (3*(2^130-6)) % (2^130-5)
                InputHex = "fafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffff" +
                           "fffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (3*(2^130-5)) % (2^130-5)
                InputHex = "fbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffff" +
                           "fffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "f7ffffffffffffffffffffffffffffff", // (4*(2^130-6)) % (2^130-5)
                InputHex = "fafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffff" +
                           "ffffffffaffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "0000000000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (4*(2^130-5)) % (2^130-5)
                InputHex = "fbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffff" +
                           "ffffffffbffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "0000000000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "f3ffffffffffffffffffffffffffffff", // (8*(2^130-6)) % (2^130-5)
                InputHex = "fafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffff" +
                           "ffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffaffffffffffffffff" +
                           "fffffffffffffffafffffffffffffffffffffffffffffffaffffffffffffffffffffffffffffff00000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (8*(2^130-5)) % (2^130-5)
                InputHex = "fbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffff" +
                           "ffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbffffffffffffffff" +
                           "fffffffffffffffbfffffffffffffffffffffffffffffffbffffffffffffffffffffffffffffff00000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "ebffffffffffffffffffffffffffffff", // (16*(2^130-6)) % (2^130-5)
                InputHex = "fafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffff" +
                           "ffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffaffffffffffffffff" +
                           "fffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffff" +
                           "ffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffaff" +
                           "fffffffffffffffffffffffffffffafffffffffffffffffffffffffffffffafffffffffffffffffffffffffff" +
                           "ffffafffffffffffffffffffffffffffffffaffffffffffffffffffffffffffffff0000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000",
            },
            new Poly1305TestVector
            {
                KeyHex = "0100000000000000000000000000000000000000000000000000000000000000",
                TagHex = "00000000000000000000000000000000", // (16*(2^130-5)) % (2^130-5)
                InputHex = "fbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffff" +
                           "ffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbffffffffffffffff" +
                           "fffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffff" +
                           "ffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbff" +
                           "fffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffbfffffffffffffffffffffffffff" +
                           "ffffbfffffffffffffffffffffffffffffffbffffffffffffffffffffffffffffff0000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                           "00000000000000000000000",
            },

            // randomly generated
            new Poly1305TestVector
            {
                KeyHex = "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649",
                TagHex = "9566c74d10037c4d7bbb0407d1e2c649",
                InputHex = "",
            },
            new Poly1305TestVector
            {
                KeyHex = "81855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999",
                TagHex = "eaa270caaa12faa39b797374a4b8a420",
                InputHex = "eb",
            },
            new Poly1305TestVector
            {
                KeyHex = "9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f15f",
                TagHex = "dbea66e1da48a8f822887c6162c2acf1",
                InputHex = "b90b",
            },
            new Poly1305TestVector
            {
                KeyHex = "adb37c5821b6d95526a41a9504680b4e7c8b763a1b1d49d4955c848621632525",
                TagHex = "6ac09aaa88c32ee95a7198376f16abdb",
                InputHex = "3fec73",
            },
            new Poly1305TestVector
            {
                KeyHex = "8dd7a9e28bf921119c160f0702448615bbda08313f6a8eb668d20bf505987592",
                TagHex = "b1443487f97fe340b04a74719ed4de68",
                InputHex = "1e668a5b",
            },
            new Poly1305TestVector
            {
                KeyHex = "df2c7fc4844592d2572bcd0668d2d6c52f5054e2d0836bf84c7174cb7476364c",
                TagHex = "7463be0f9d99a5348039e4afcbf4019c",
                InputHex = "c3dbd968b0",
            },
            new Poly1305TestVector
            {
                KeyHex = "f7172ed85794bb358b0c3b525da1786f9fff094279db1944ebd7a19d0f7bbacb",
                TagHex = "2edaee3bcf303fd05609e131716f8157",
                InputHex = "e0255aa5b7d4",
            },
            new Poly1305TestVector
            {
                KeyHex = "4bec40f84c892b9bffd43629b0223beea5f4f74391f445d15afd4294040374f6",
                TagHex = "965f18767420c1d94a4ef657e8d15e1e",
                InputHex = "924b98cbf8713f",
            },
            new Poly1305TestVector
            {
                KeyHex = "8d962d7c8d019192c24224e2cafccae3a61fb586b14323a6bc8f9e7df1d92933",
                TagHex = "2bf4a33287dd6d87e1ed4282f7342b6a",
                InputHex = "3ff993933bea6f5b",
            },
            new Poly1305TestVector
            {
                KeyHex = "3af6de0374366c4719e43a1b067d89bc7f01f1f573981659a44ff17a4c7215a3",
                TagHex = "c5e987b60373a48893c5af30acf2471f",
                InputHex = "b539eb1e5849c6077d",
            },
            new Poly1305TestVector
            {
                KeyHex = "bb5722f5717a289a266f97647981998ebea89c0b4b373970115e82ed6f4125c8",
                TagHex = "19f0f640b309d168ea1b480e6a4faee5",
                InputHex = "fa7311e4d7defa922daa",
            },
            new Poly1305TestVector
            {
                KeyHex = "e7786667f7e936cd4f24abf7df866baa56038367ad6145de1ee8f4a8b0993ebd",
                TagHex = "de75e5565d97834b9fa84ad568d31359",
                InputHex = "f8883a0ad8be9c3978b048",
            },
            new Poly1305TestVector
            {
                KeyHex = "83e56a156a8de563afa467d49dec6a40e9a1d007f033c2823061bdd0eaa59f8e",
                TagHex = "de184a5a9b826aa203c5c017986d6690",
                InputHex = "4da6430105220d0b29688b73",
            },
            new Poly1305TestVector
            {
                KeyHex = "4b8ea0f3ca9936e8461f10d77c96ea80a7a665f606f6a63b7f3dfd2567c18979",
                TagHex = "7478f18d9684905aa5d1a34ee67e4c84",
                InputHex = "e4d60f26686d9bf2fb26c901ff",
            },
            new Poly1305TestVector
            {
                KeyHex = "354cde1607ee294b39f32b7c7822ba64f84ab43ca0c6e6b91c1fd3be89904341",
                TagHex = "3b2008a9c52b5308f5538b789ab5506f",
                InputHex = "79d3af4491a369012db92d184fc3",
            },
            new Poly1305TestVector
            {
                KeyHex = "9d1734ff5716428953bb6865fcf92b0c3a17c9028be9914eb7649c6c93478009",
                TagHex = "71c8e76a67a505b7370b562ba15ba032",
                InputHex = "79d1830356f2a54c3deab2a4b4475d",
            },
            new Poly1305TestVector
            {
                KeyHex = "63afbe8fb56987c77f5818526f1814be823350eab13935f31d84484517e924ae",
                TagHex = "1dc895f74f866bdb3edf6c4430829c1c",
                InputHex = "f78ae151c00755925836b7075885650c",
            },
            new Poly1305TestVector
            {
                KeyHex = "30ec29a3703934bf50a28da102975deda77e758579ea3dfe4136abf752b3b827",
                TagHex = "afca2b3ba7b0e1a928001966883e9b16",
                InputHex = "1d03e944b3c9db366b75045f8efd69d22ae5411947cb553d7694267aef4ebcea406b32d6108bd68584f57e37c" +
                           "aac6e33feaa3263a399437024ba9c9b14678a274f01a910ae295f6efbfe5f5abf44ccde263b5606633e2bf000" +
                           "6f28295d7d39069f01a239c4365854c3af7f6b41d631f92b9a8d12f41257325fff332f7576b0620556304a3e3" +
                           "eae14c28d0cea39d2901a52720da85ca1e4b38eaf3f",
            },
        };

        //
        // XChaCha20Poly1305
        //

        public struct XChaCha20Poly1305TestVector
        {
            public byte[] Plaintext => PlaintextHex.DecodeHex();
            public byte[] Ciphertext => CiphertextHex.DecodeHex();
            public byte[] Nonce => NonceHex.DecodeHex();
            public byte[] AssociatedData => AssociatedDataHex.DecodeHex();
            public byte[] Key => KeyHex.DecodeHex();

            internal string PlaintextHex;
            internal string CiphertextHex;
            internal string NonceHex;
            internal string AssociatedDataHex;
            internal string KeyHex;
        }

        // From https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_vectors_test.go
        public static readonly XChaCha20Poly1305TestVector[] XChaCha20Poly1305TestVectors =
        {
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "000000000000000000000000000000",
                AssociatedDataHex = "",
                KeyHex = "0000000000000000000000000000000000000000000000000000000000000000",
                NonceHex = "000000000000000000000000000000000000000000000000",
                CiphertextHex = "789e9689e5208d7fd9e1f3c5b5341fb2f7033812ac9ebd3745e2c99c7bbfeb",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "02dc819b71875e49f5e1e5a768141cfd3f14307ae61a34d81decd9a3367c00c7",
                AssociatedDataHex = "",
                KeyHex = "b7bbfe61b8041658ddc95d5cbdc01bbe7626d24f3a043b70ddee87541234cff7",
                NonceHex = "e293239d4c0a07840c5f83cb515be7fd59c333933027e99c",
                CiphertextHex = "7a51f271bd2e547943c7be3316c05519a5d16803712289aa2369950b1504dd8267222e47b13280077eca" +
                                "da7b8795d535",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "7afc5f3f24155002e17dc176a8f1f3a097ff5a991b02ff4640f70b90db0c15c328b696d6998ea7988edfe" +
                               "3b960e47824e4ae002fbe589be57896a9b7bf5578599c6ba0153c7c",
                AssociatedDataHex = "d499bb9758debe59a93783c61974b7",
                KeyHex = "4ea8fab44a07f7ffc0329b2c2f8f994efdb6d505aec32113ae324def5d929ba1",
                NonceHex = "404d5086271c58bf27b0352a205d21ce4367d7b6a7628961",
                CiphertextHex = "26d2b46ad58b6988e2dcf1d09ba8ab6f532dc7e0847cdbc0ed00284225c02bbdb278ee8381ebd127a069" +
                                "26107d1b731cfb1521b267168926492e8f77219ad922257a5be2c5e52e6183ca4dfd0ad3912d7bd1ec96" +
                                "8065",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "",
                AssociatedDataHex = "",
                KeyHex = "48d8bd02c2e9947eae58327114d35e055407b5519c8019535efcb4fc875b5e2b",
                NonceHex = "cc0a587a475caba06f8dbc09afec1462af081fe1908c2cba",
                CiphertextHex = "fc3322d0a9d6fac3eb4a9e09b00b361e",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "e0862731e5",
                AssociatedDataHex = "",
                KeyHex = "6579e7ee96151131a1fcd06fe0d52802c0021f214960ecceec14b2b8591f62cd",
                NonceHex = "e2230748649bc22e2b71e46a7814ecabe3a7005e949bd491",
                CiphertextHex = "e991efb85d8b1cfa3f92cb72b8d3c882e88f4529d9",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "00c7dd8f440af1530b44",
                AssociatedDataHex = "",
                KeyHex = "ffb733657c849d50ab4ab40c4ae18f8ee2f0acf7c907afefdc04dff3537fdff3",
                NonceHex = "02c6fd8032a8d89edbedcd1db024c09d29f08b1e74325085",
                CiphertextHex = "13dbcdb8c60c3ed28449a57688edfaea89e309ab4faa6d51e532",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "7422f311ea476cf819cb8b3c77369f",
                AssociatedDataHex = "",
                KeyHex = "ef0d05d028d6abdd5e99d1761d2028de75ee6eb376ff0dc8036e9a8e10743876",
                NonceHex = "f772745200b0f92e38f1d8dae79bf8138e84b301f0be74df",
                CiphertextHex = "d5f992f9834df1be86b580ac59c7eae063a68072829c51bc8a26970dd3d310",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "ba09ca69450e6c7bece31a7a3f216e3b9ed0e536",
                AssociatedDataHex = "",
                KeyHex = "8d93e31abfe22a63faf45cbea91877050718f13fef6e2664a1892d7f23007ccf",
                NonceHex = "260b7b3554a7e6ff8aae7dd6234077ca539689a20c1610a8",
                CiphertextHex = "c99e9a768eb2ec8569bdff8a37295069552faebcafb1a76e98bc7c5b6b778b3d1b6291f0",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "424ec5f98a0fdc5a7388532d11ab0edb26733505627b7f2d1f",
                AssociatedDataHex = "",
                KeyHex = "b68d5e6c46cdbb0060445522bdc5c562ae803b6aaaf1e103c146e93527a59299",
                NonceHex = "80bb5dc1dd44a35ec4f91307f1a95b4ca31183a1a596fb7c",
                CiphertextHex = "29d4eed0fff0050d4bb40de3b055d836206e7cbd62de1a63904f0cf731129ba3f9c2b9d46251a6de89",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "e7e4515cc0a6ef0491af983eaac4f862d6e726758a3c657f4ec444841e42",
                AssociatedDataHex = "",
                KeyHex = "e31a1d3af650e8e2848bd78432d89ecd1fdece9842dc2792e7bda080f537b17b",
                NonceHex = "f3f09905e9a871e757348834f483ed71be9c0f437c8d74b0",
                CiphertextHex = "f5c69528963e17db725a28885d30a45194f12848b8b7644c7bded47a2ee83e6d4ef34006305cfdf82eff" +
                                "dced461d",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "0f5ca45a54875d1d19e952e53caeaa19389342f776dab11723535503338d6f77202a37",
                AssociatedDataHex = "",
                KeyHex = "1031bc920d4fcb4434553b1bf2d25ab375200643bf523ff037bf8914297e8dca",
                NonceHex = "4cc77e2ef5445e07b5f44de2dc5bf62d35b8c6f69502d2bf",
                CiphertextHex = "7aa8669e1bfe8b0688899cdddbb8cee31265928c66a69a5090478da7397573b1cc0f64121e7d8bff8db0" +
                                "ddd3c17460d7f29a12",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "c45578c04c194994e89025c7ffb015e5f138be3cd1a93640af167706aee2ad25ad38696df41ad805",
                AssociatedDataHex = "",
                KeyHex = "ac8648b7c94328419c668ce1c57c71893adf73abbb98892a4fc8da17400e3a5e",
                NonceHex = "4ad637facf97af5fc03207ae56219da9972858b7430b3611",
                CiphertextHex = "49e093fcd074fb67a755669119b8bd430d98d9232ca988882deeb3508bde7c00160c35cea89092db864d" +
                                "cb6d440aefa5aacb8aa7b9c04cf0",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "b877bfa192ea7e4c7569b9ee973f89924d45f9d8ed03c7098ad0cad6e7880906befedcaf6417bb43efabc" +
                               "a7a2f",
                AssociatedDataHex = "",
                KeyHex = "125e331d5da423ecabc8adf693cdbc2fc3d3589740d40a3894f914db86c02492",
                NonceHex = "913f8b2f08006e6260de41ec3ee01d938a3e68fb12dc44c4",
                CiphertextHex = "1be334253423c90fc8ea885ee5cd3a54268c035ba8a2119e5bd4f7822cd7bf9cb4cec568d5b6d6292606" +
                                "d32979e044df3504e6eb8c0b2fc7e2a0e17d62",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "d946484a1df5f85ff72c92ff9e192660cde5074bd0ddd5de900c35eb10ed991113b1b19884631bc8ceb38" +
                               "6bcd83908061ce9",
                AssociatedDataHex = "",
                KeyHex = "b7e83276373dcf8929b6a6ea80314c9de871f5f241c9144189ee4caf62726332",
                NonceHex = "f59f9d6e3e6c00720dc20dc21586e8330431ebf42cf9180e",
                CiphertextHex = "a38a662b18c2d15e1b7b14443cc23267a10bee23556b084b6254226389c414069b694159a4d0b5abbe34" +
                                "de381a0e2c88b947b4cfaaebf50c7a1ad6c656e386280ad7",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "d266927ca40b2261d5a4722f3b4da0dd5bec74e103fab431702309fd0d0f1a259c767b956aa7348ca923d" +
                               "64c04f0a2e898b0670988b15e",
                AssociatedDataHex = "",
                KeyHex = "a60e09cd0bea16f26e54b62b2908687aa89722c298e69a3a22cf6cf1c46b7f8a",
                NonceHex = "92da9d67854c53597fc099b68d955be32df2f0d9efe93614",
                CiphertextHex = "9dd6d05832f6b4d7f555a5a83930d6aed5423461d85f363efb6c474b6c4c8261b680dea393e24c2a3c8d" +
                                "1cc9db6df517423085833aa21f9ab5b42445b914f2313bcd205d179430",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "f7e11b4d372ed7cb0c0e157f2f9488d8efea0f9bbe089a345f51bdc77e30d1392813c5d22ca7e2c7dfc2e" +
                               "2d0da67efb2a559058d4de7a11bd2a2915e",
                AssociatedDataHex = "",
                KeyHex = "194b1190fa31d483c222ec475d2d6117710dd1ac19a6f1a1e8e894885b7fa631",
                NonceHex = "6b07ea26bb1f2d92e04207b447f2fd1dd2086b442a7b6852",
                CiphertextHex = "25ae14585790d71d39a6e88632228a70b1f6a041839dc89a74701c06bfa7c4de3288b7772cb2919818d9" +
                                "5777ab58fe5480d6e49958f5d2481431014a8f88dab8f7e08d2a9aebbe691430011d",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "",
                AssociatedDataHex = "1e2b11e3",
                KeyHex = "70cd96817da85ede0efdf03a358103a84561b25453dee73735e5fb0161b0d493",
                NonceHex = "5ddeba49f7266d11827a43931d1c300dd47a3c33f9f8bf9b",
                CiphertextHex = "592fc4c19f3cddec517b2a00f9df9665",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "81b3cb7eb3",
                AssociatedDataHex = "efcfd0cf",
                KeyHex = "a977412f889281a6d75c24186f1bfaa00dcc5132f0929f20ef15bbf9e63c4c91",
                NonceHex = "3f26ca997fb9166d9c615babe3e543ca43ab7cab20634ac5",
                CiphertextHex = "8e4ade3e254cf52e93eace5c46667f150832725594",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "556f97f2ebdb4e949923",
                AssociatedDataHex = "f7cee2e0",
                KeyHex = "787b3e86546a51028501c801dadf8d5b996fd6f6f2363d5d0f900c44f6a2f4c2",
                NonceHex = "7fa6af59a779657d1cada847439ea5b92a1337cfbebbc3b1",
                CiphertextHex = "608ec22dae5f48b89d6f0d2a940d5a7661e0a8e68aaee4ad2d96",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "c06847a36ad031595b60edd44dc245",
                AssociatedDataHex = "d4175e1f",
                KeyHex = "16de31e534dd5af32801b1acd0ec541d1f8d82bcbc3af25ec815f3575b7aca73",
                NonceHex = "29f6656972838f56c1684f6a278f9e4e207b51d68706fc25",
                CiphertextHex = "836082cc51303e500fceade0b1a18f1d97d64ff41cc81754c07d6231b9fd1b",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "0d03c22ced7b29c6741e72166cd61792028dfc80",
                AssociatedDataHex = "e505dad0",
                KeyHex = "ac2b426e5c5c8e00666180a3410e8a2f6e52247a43aecea9622163e8433c93b2",
                NonceHex = "c1123430468228625967bbc0fbd0f963e674372259ff2deb",
                CiphertextHex = "bf09979bf4fed2eec6c97f6e1bcfac35eeffc6d54a55cc1d83d8767ae74db2d7cdfbc371",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "05bf00e1707cffe7ccbd06a9f846d0fd471a700ed43b4facb8",
                AssociatedDataHex = "d863bebe",
                KeyHex = "66c121f0f84b95ba1e6d29e7d81900bc96a642421b9b6105ae5eb5f2e7b07577",
                NonceHex = "8ed6ae211a661e967995b71f7316ba88f44322bb62b4187b",
                CiphertextHex = "b2c5c85d087e0305e9058fba52b661fb3d7f21cb4d4915ae048bc9e5d66a2f921dd4a1c1b030f442c9",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "5f2b91a9be8bfaa21451ddc6c5cf28d1cc00b046b76270b95cda3c280c83",
                AssociatedDataHex = "a8750275",
                KeyHex = "39592eb276877fca9dd11e2181c0b23127328407e3cc11e315e5d748f43529cc",
                NonceHex = "1084bebd756f193d9eea608b3a0193a5028f8ced19684821",
                CiphertextHex = "eaee1f49ac8468154c601a5dd8b84d597602e5a73534b5fad5664f97d0f017dd114752be969679cf6103" +
                                "40c6a312",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "01e8e269b5376943f3b2d245483a76461dc8b7634868b559165f5dbb20839029fae9bb",
                AssociatedDataHex = "a1e96da0",
                KeyHex = "b8386123b87e50d9d046242cf1bf141fce7f65aff0fba76861a2bc72582d6ff0",
                NonceHex = "0fbe2a13a89bea031de96d78f9f11358ba7b6a5e724b4392",
                CiphertextHex = "705ec3f910ec85c6005baa99641de6ca43332ff52b5466df6af4ffbe4ef2a376a8f871d1eae503b58966" +
                                "01fee005cdc1f4c1c6",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "706daba66e2edb1f828f3c0051e3cc214b12210bde0587bba02580f741a4c83e84d4e9fe961120cd",
                AssociatedDataHex = "87663c5a",
                KeyHex = "d519d82ba8a3f0c3af9efe36682b62e285167be101a526c1d73000f169c2a486",
                NonceHex = "ad651aac536978e2bc1a54816345ac5e9a9b43b3d9cc0bfc",
                CiphertextHex = "07051b5e72da9c4811beb07ff9f95aece67eae18420eb3f0e8bb8a5e26d4b483fa40eb063a2354842d0c" +
                                "8a41d981cc2b77c530b496db01c8",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "1f6b24f2f0d9eb460d726bed953d66fcc4ecc29da6ed2fd711358eac3b2609d74ba3e21885156cde3cbe6" +
                               "d9b6f",
                AssociatedDataHex = "f5efbc4e",
                KeyHex = "86068a00544f749ad4ad15bb8e427ae78577ae22f4ca9778efff828ba10f6b20",
                NonceHex = "c8420412c9626dcd34ece14593730f6aa2d01ec51cacd59f",
                CiphertextHex = "a99f6c88eac35bb34439e34b292fe9db8192446dcdc81e2192060ec36d98b47de2bee12bf0f67cb24fb0" +
                                "949c07733a6781cd9455cdc61123f506886b04",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "d69389d83362be8c0ddb738659a6cc4bd65d88cb5b525232f4d59a7d4751a7203c254923ecb6873e80322" +
                               "0aab19664789a63",
                AssociatedDataHex = "bc35fb1c",
                KeyHex = "835855b326a98682b3075b4d7f1b89059c3cdfc547d4296c80ce7a77ba6434e3",
                NonceHex = "c27cb75fc319ba431cbaeb120341d0c4745d883eb47e92bc",
                CiphertextHex = "db6dc3f9a0f4f1a6df2495a88910550c2c6205478bfc1e81282e34b5b36d984c72c0509c522c987c61d2" +
                                "e640ced69402a6d33aa10d3d0b81e680b3c19bc142e81923",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "a66a7f089115ed9e2d5bb5d33d7282a7afe401269b00f2a233a59c04b794a42901d862140b61d18d7c7f0" +
                               "ad5da040613e557f8abc74219",
                AssociatedDataHex = "2c060aaf",
                KeyHex = "99758aa7714fd707931f71803eefe04a06955041308a0b2a1104313b270ccf34",
                NonceHex = "63f690d8926408c7a34fe8ddd505a8dc58769dc74e8d5da6",
                CiphertextHex = "92b21ee85afcd8996ac28f3aed1047ad814d6e4ffbca3159af16f26eded83e4abda9e4275eb3ff0ad90d" +
                                "ffe09f2d443b628f824f680b46527ce0128e8de1920f7c44350ebe7913",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "f955183b1f762d4536d3f6885ea7f5ac27414caf46c2e24a2fd3bd56b91c53d840fb657224565e0a6f686" +
                               "f8ba320e04a401057399d9a3d995ab17c13",
                AssociatedDataHex = "c372ddc5",
                KeyHex = "a188be3795b2ca2e69b6aa263244f0963c492d694cf6c9b705a1d7045f3f2a26",
                NonceHex = "51bb484ea094ee140474681e1c838e4442fd148de2cc345a",
                CiphertextHex = "48759a5ddfdd829d11de8e0c538ce4a9c475faab6912039b568ad92d737d172fc1eb0c00c3793de6dddb" +
                                "facfdbbc7f44aeba33684e18005aa982b6fc6c556e63bb90ff7a1dde8153a63eabe0",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "",
                AssociatedDataHex = "e013cd0bfafd486d",
                KeyHex = "af3d3ba094d38299ecb91c17bfe3d085da5bd42e11acf8acb5bc26a4be9a7583",
                NonceHex = "7dd63c14173831f109761b1c1abe18f6ba937d825957011b",
                CiphertextHex = "8bc685a7d9d501952295cd25d8c92517",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "284b64597e",
                AssociatedDataHex = "31d013e53aa3ea79",
                KeyHex = "93c77409d7f805f97fe683b2dd6ee06152a5e918b3eed5b731acccffdcb2cc04",
                NonceHex = "3d331e90c4597cf0c30d1b7cfbd07bcb6ab927eda056873c",
                CiphertextHex = "3538a449d6c18d148a8c6cb76f1bc288657ac7036a",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "9fe67f5c78180ede8274",
                AssociatedDataHex = "188608d230d75860",
                KeyHex = "b7cca89a82640aea6f80b458c9e633d88594fb498959d39787be87030892d48f",
                NonceHex = "ef891d50e8c08958f814590fdb7a9f16c61cc2aae1682109",
                CiphertextHex = "bbb40c30f3d1391a5b38df480cbbf964b71e763e8140751f4e28",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "3a2826b6f7e3d542e4ded8f23c9aa4",
                AssociatedDataHex = "260033e789c4676a",
                KeyHex = "7fe2731214f2b4b42f93217d43f1776498413725e4f6cfe62b756e5a52df10ea",
                NonceHex = "888728219ebf761547f5e2218532714403020e5a8b7a49d0",
                CiphertextHex = "fe0328f883fcd88930ae017c0f54ed90f883041efc020e959125af370c1d47",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "91858bf7b969005d7164acbd5678052b651c53e0",
                AssociatedDataHex = "f3cc53ecafcbadb3",
                KeyHex = "d69c04e9726b22d51f97bc9da0f0fda86736e6b78e8ef9f6f0000f79890d6d43",
                NonceHex = "6de3c45161b434e05445cf6bf69eef7bddf595fc6d8836bd",
                CiphertextHex = "a8869dd578c0835e120c843bb7dedc7a1e9eae24ffd742be6bf5b74088a8a2c550976fcb",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "b3b1a4d6b2a2b9c5a1ca6c1efaec34dcfa1acbe7074d5e10cc",
                AssociatedDataHex = "d0f72bd16cda3bae",
                KeyHex = "2b317857b089c9305c49b83019f6e158bc4ecc3339b39ade02ee10c37c268da0",
                NonceHex = "cb5fa6d1e14a0b4bdf350cd10c8a7bd638102911ec74be09",
                CiphertextHex = "e6372f77c14343650074e07a2b7223c37b29242224b722b24d63b5956f27aa64ce7ce4e39cd14a2787",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "057d3e9f865be7dff774938cab6d080e50cf9a1593f53c0063201e0bb7ae",
                AssociatedDataHex = "fd3881e505c8b12d",
                KeyHex = "36e42b1ef1ee8d068f09b5fad3ee43d98d34aa3e3f994f2055aee139da71de9d",
                NonceHex = "24124da36473d01bdca30297c9eef4fe61955525a453da17",
                CiphertextHex = "a8b28139524c98c1f8776f442eac4c22766fe6aac83224641c58bf021fc9cb709ec4706f49c2d0c1828a" +
                                "cf2bfe8d",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "bd8f13e928c34d67a6c70c3c7efdf2982ecc31d8cee68f9cbddc75912cd828ac93d28b",
                AssociatedDataHex = "193206c8fcc5b19b",
                KeyHex = "6e47c40c9d7b757c2efca4d73890e4c73f3c859aab4fdc64b564b8480dd84e72",
                NonceHex = "ca31340ae20d30fe488be355cb36652c5db7c9d6265a3e95",
                CiphertextHex = "a121efc5e1843deade4b8adbfef1808de4eda222f176630ad34fb476fca19e0299e4a13668e53cf13882" +
                                "035ba4f04f47c8b4e3",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "23067a196e977d10039c14ff358061c918d2148d31961bb3e12c27c5122383cb25c4d1d79c775720",
                AssociatedDataHex = "62338d02fff78a00",
                KeyHex = "2c5c79c92d91fb40ef7d0a77e8033f7b265e3bab998b8116d17b2e62bb4f8a09",
                NonceHex = "024736adb1d5c01006dffd8158b57936d158d5b42054336d",
                CiphertextHex = "46d0905473a995d38c7cdbb8ef3da96ecc82a22c5b3c6c9d1c4a61ae7a17db53cb88c5f7eccf2da1d0c4" +
                                "17c300f989b4273470e36f03542f",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "252e966c680329eb687bff813b78fea3bfd3505333f106c6f9f45ba69896723c41bb763793d9b266e897d" +
                               "05557",
                AssociatedDataHex = "1e93e0cfe6523380",
                KeyHex = "9ec6fd1baa13ee16aec3fac16718a2baccf18a403cec467c25b7448e9b321110",
                NonceHex = "e7120b1018ab363a36e61102eedbcbe9847a6cbacaa9c328",
                CiphertextHex = "2934f034587d4144bb11182679cd2cd1c99c8088d18e233379e9bc9c41107a1f57a2723ecc7b9ba4e6ee" +
                                "198adf0fd766738e828827dc73136fc5b996e9",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "6744aefcb318f12bc6eeb59d4d62f7eb95f347cea14bd5158415f07f84e4e3baa3de07512d9b76095ac13" +
                               "12cfcb1bb77f499",
                AssociatedDataHex = "608d2a33ce5d0b04",
                KeyHex = "0f665cbdaaa40f4f5a00c53d951b0a98aac2342be259a52670f650a783be7aab",
                NonceHex = "378bdb57e957b8c2e1500c9513052a3b02ff5b7edbd4a3a7",
                CiphertextHex = "341c60fcb374b394f1b01a4a80aedef49ab0b67ec963675e6eec43ef106f7003be87dbf4a8976709583d" +
                                "ccc55abc7f979c4721837e8664a69804ea31736aa2af615a",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "bcf1004f988220b7ce063ef2ec4e276ffd074f0a90aa807de1532679d2a1505568eaa4192d9a6ea52cc50" +
                               "0322343ce9f8e68cc2c606d83",
                AssociatedDataHex = "e64bd00126c8792c",
                KeyHex = "58e65150d6a15dcefbc14a171998987ad0d709fb06a17d68d6a778759681c308",
                NonceHex = "106d2bd120b06e4eb10bc674fe55c77a3742225268319303",
                CiphertextHex = "a28052a6686a1e9435fee8702f7da563a7b3d7b5d3e9e27f11abf73db309cd1f39a34756258c1c5c7f2f" +
                                "b12cf15eb20175c2a08fc93dd19c5e482ef3fbef3d8404a3cfd54a7baf",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "acd08d4938a224b4cb2d723bf75420f3ea27b698fadd815bb7db9548a05651398644354334e69f8e4e550" +
                               "3bf1a6f92b38e860044a7edca6874038ce1",
                AssociatedDataHex = "28a137808d0225b8",
                KeyHex = "a031203b963a395b08be55844d81af39d19b23b7cc24b21afa31edc1eea6edd6",
                NonceHex = "e8b31c52b6690f10f4ae62ba9d50ba39fb5edcfb78400e35",
                CiphertextHex = "35cf39ba31da95ac9b661cdbd5e9c9655d13b8ff065c4ec10c810833a47a87d8057dd1948a7801bfe690" +
                                "4b49fed0aabfb3cd755a1a262d372786908ddcf64cae9f71cb9ed199c3ddacc50116",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "",
                AssociatedDataHex = "cda7ee2857e09e9054ef6806",
                KeyHex = "d91dffb18132d8dd3d144a2f10ba28bc5df36cb60369f3b19893ec91db3cf904",
                NonceHex = "ee56f19c62b0438da6a0d9e01844313902be44f84a6a4ce7",
                CiphertextHex = "ccd48b61a5683c195d4424009eb1d147",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "350f4c7ac2",
                AssociatedDataHex = "7c104b539c1d2ae022434cd6",
                KeyHex = "cbb61e369117f9250f68fa707240c554359262a4d66c757f80e3aeb6920894fb",
                NonceHex = "fbb14c9943444eac5413c6f5c8095451eddece02c9461043",
                CiphertextHex = "b5c6a35865ed8e5216ff6c77339ee1ab570de50e51",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "4f0d61d3ea03a44a8df0",
                AssociatedDataHex = "51c20a8ae9e9794da931fe23",
                KeyHex = "ba6ced943aa62f9261d7513b822e02054e099acafb5360f0d850064da48b5a4f",
                NonceHex = "04c68cb50cdbb0ec03f8381cf59b886e64c40548bf8e3f82",
                CiphertextHex = "ea45a73957e2a853655623f2a3bb58791f7ea36dd2957ed66ffa",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "4fbdd4d4293a8f34fdbc8f3ad44cf6",
                AssociatedDataHex = "8212f315e3759c3253c588bb",
                KeyHex = "5354791bc2370415811818e913e310dd12e6a0cf5dcab2b6424816eecccf4b65",
                NonceHex = "7ee6353c2fbc73c9ebc652270bc86e4008e09583e623e679",
                CiphertextHex = "50a354811a918e1801fb567621a8924baf8dd79da6d36702855d3753f1319c",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "5a6f68b5a9a9920ca9c6edf5be7c0af150a063c4",
                AssociatedDataHex = "9a524aa62938fb7a1e50ed06",
                KeyHex = "fd91605a6ad85d8ba7a71b08dce1032aa9992bf4f28d407a53ddda04c043cada",
                NonceHex = "46791d99d6de33e79025bf9e97c198e7cf409614c6284b4d",
                CiphertextHex = "648033c1eb615467e90b7d3ac24202d8b849549141f9bab03e9e910c29b8eab3d4fb3f2c",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "d9318c2c0d9ed89e35d242a6b1d496e7e0c5bbdf77eba14c56",
                AssociatedDataHex = "a16053c35fbe8dc93c14a81f",
                KeyHex = "f21406aec83134ebf7bc48c6d0f45acb5f341fbc7d3b5a9bff3ea1333c916af7",
                NonceHex = "de6b977be450d5efa7777e006802ddbb10814a22da1c3cd9",
                CiphertextHex = "8d3dad487d5161663da830b71c3e24ec5cdb74d858cbb73b084ed0902198532aad3a18416966bff223",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "68d0ee08d38cb4bcc9268fee3030666e70e41fcabf6fe06536eeec43eec5",
                AssociatedDataHex = "11e09447d40b22dc98070eec",
                KeyHex = "da5ee1ec02eab13220fcb94f16efec848a8dd57c0f4d67955423f5d17fde5aa3",
                NonceHex = "8f13e61d773a250810f75d46bf163a3f9205be5751f6049a",
                CiphertextHex = "92a103b03764c1ad1f88500d22eeae5c0fe1044c872987c0b97affc5e8c3d783f8cc28a11dc91990ea22" +
                                "dd1bad74",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "a1d960bda08efcf19e136dc1e8b05b6b381c820eda5f9a8047e1a2dd1803a1e4d11a7f",
                AssociatedDataHex = "aa73d8d4aaa0cfd9d80a9ae8",
                KeyHex = "08028833d617c28ba75b48f177cb5da87189189abb68dcb8974eca9230c25945",
                NonceHex = "f7b6f34a910fd11588f567de8555932291f7df05f6e2b193",
                CiphertextHex = "99cfc4cca193998bae153b744e6c94a82a2867780aa0f43acddb7c433fcb297311313ec2199f00d7ca7d" +
                                "a0646b40113c60e935",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "3b4ae39a745b6247ce5baf675ec36c5065b1bf76c8379eab4b769961d43a753896d068938017777e",
                AssociatedDataHex = "128c017a985052f8cdbc6b28",
                KeyHex = "4683d5caff613187a9b16af897253848e9c54fc0ec319de62452a86961d3cbb2",
                NonceHex = "5612a13c2da003b91188921cbac3fa093eba99d8cbbb51ff",
                CiphertextHex = "91a98b93b2174257175f7c882b45cc252e0db8667612bd270c1c12fe28b6bf209760bf8f370318f92ae3" +
                                "f88a5d4773b05714132cc28dddb8",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "22ccf680d2995ef6563de281cff76882a036a59ad73f250e710b3040590d69bccde8a8411abe8b0d3cb72" +
                               "8ca82",
                AssociatedDataHex = "13a97d0a167a61aa21e531ec",
                KeyHex = "9e140762eed274948b66de25e6e8f36ab65dc730b0cb096ef15aaba900a5588c",
                NonceHex = "d0e9594cfd42ab72553bf34062a263f588bb8f1fc86a19f5",
                CiphertextHex = "f194fc866dfba30e42c4508b7d90b3fa3f8983831ede713334563e36aa861f2f885b40be1dbe20ba2d10" +
                                "958a12823588d4bbbefb81a87d87315204f5e3",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "a65f5d10c482b3381af296e631eb605eba6a11ccec6ceab021460d0bd35feb676ec6dbba5d4ad6c9f4d68" +
                               "3ea541035bc80fa",
                AssociatedDataHex = "f15ae71ffed50a8fcc4996b0",
                KeyHex = "f535d60e8b75ac7e526041eed86eb4d65ae7e315eff15dba6c0133acc2a6a4bf",
                NonceHex = "01ba61691ebb3c66d2f94c1b1c597ecd7b5ff7d2a30be405",
                CiphertextHex = "d79e7c3893df5a5879c2f0a3f7ca619f08e4540f3ac7db35790b4211b9d47ae735adadf35fd47252a476" +
                                "3e3fd2b2cd8157f6ea7986108a53437962670a97d68ee281",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "8c014655b97f6da76b0b168b565fd62de874c164fd7e227346a0ec22c908bed1e2a0b429620e6f3a68dd5" +
                               "18f13a2c0250608a1cb08a7c3",
                AssociatedDataHex = "10a7eff999029c5040c1b3bd",
                KeyHex = "bf11af23e88c350a443493f6fa0eb34f234f4daa2676e26f0701bce5642d13f4",
                NonceHex = "f14c97392afd2e32e2c625910ca029f9b6e81676c79cc42f",
                CiphertextHex = "78d5226f372d5d60681dbfc749d12df74249f196b0cbf14fa65a3a59dc65ae458455ec39baa1df3397af" +
                                "e752bb06f6f13bf03c99abda7a95c1d0b73fd92d5f888a5f6f889a9aea",
            },
            new XChaCha20Poly1305TestVector
            {
                PlaintextHex = "66234d7a5b71eef134d60eccf7d5096ee879a33983d6f7a575e3a5e3a4022edccffe7865dde20b5b0a372" +
                               "52e31cb9a3650c63e35b057a1bc200a5b5b",
                AssociatedDataHex = "ccc2406f997bcae737ddd0f5",
                KeyHex = "d009eeb5b9b029577b14d200b7687b655eedb7d74add488f092681787999d66d",
                NonceHex = "99319712626b400f9458dbb7a9abc9f5810f25b47fc90b39",
                CiphertextHex = "543a2bbf52fd999027ae7c297353f3ce986f810bc2382583d0a81fda5939e4c87b6e8d262790cd614d6f" +
                                "753d8035b32adf43acc7f6d4c2c44289538928564b6587c2fcb99de1d8e34ffff323",
            },
        };
    }
}
