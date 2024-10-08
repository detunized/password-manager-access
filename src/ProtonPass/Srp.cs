// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Linq;
using System.Numerics;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Srp
    {
        public class Proofs
        {
            public byte[] ClientEphemeral { get; }
            public byte[] ClientProof { get; }
            public byte[] ServerProof { get; }

            public Proofs(byte[] clientEphemeral, byte[] clientProof, byte[] serverProof)
            {
                ClientEphemeral = clientEphemeral;
                ClientProof = clientProof;
                ServerProof = serverProof;
            }
        }

        public static Proofs GenerateProofs(
            int version,
            string password,
            string username,
            byte[] saltBytes,
            byte[] serverEphemeralBytes,
            byte[] modulusBytes
        )
        {
            return GenerateProofs(
                bitLength: BitLength,
                hashedPasswordBytes: HashPassword(version, password, username, saltBytes, modulusBytes),
                serverEphemeralBytes: serverEphemeralBytes,
                modulusBytes: modulusBytes
            );
        }

        //
        // Internal, exposed for testing purposes only
        //

        internal static Proofs GenerateProofs(int bitLength, byte[] hashedPasswordBytes, byte[] serverEphemeralBytes, byte[] modulusBytes)
        {
            return GenerateProofs(
                bitLength: bitLength,
                hashedPasswordBytes: hashedPasswordBytes,
                serverEphemeralBytes: serverEphemeralBytes,
                modulusBytes: modulusBytes,
                getRandomBigInt: GetRandomBigInteger
            );
        }

        internal static Proofs GenerateProofs(
            int bitLength,
            byte[] hashedPasswordBytes,
            byte[] serverEphemeralBytes,
            byte[] modulusBytes,
            Func<BigInteger, BigInteger, BigInteger> getRandomBigInt
        )
        {
            // This code is adapted from https://github.com/ProtonMail/go-srp/blob/master/srp.go
            // The original code is MIT licensed.
            // There's a lot of crypto mumbo-jumbo going on here. We're not going to event attempt to
            // make sense of it. It works according to the tests. It's a crypto/math black box.
            var serverEphemeral = ToBigInteger(serverEphemeralBytes);
            var generator = new BigInteger(2);
            var generatorBytes = ToBytes(generator, bitLength);
            var modulus = ToBigInteger(modulusBytes);
            var modulusMinusOne = modulus - 1;
            var secret = getRandomBigInt(new BigInteger(bitLength * 2), modulusMinusOne);
            var ephemeral = generator.ModExp(secret, modulus);
            var scramblingParam = ToBigInteger(ExpandHash(Concat(ToBytes(ephemeral, bitLength), serverEphemeralBytes)));
            var multiplier = ToBigInteger(ExpandHash(Concat(generatorBytes, modulusBytes))) % modulus;
            var hashedPassword = ToBigInteger(hashedPasswordBytes);
            var baseClientSide = (serverEphemeral - generator.ModExp(hashedPassword, modulus) * multiplier % modulus) % modulus;
            var exponent = (scramblingParam * hashedPassword % modulusMinusOne + secret) % modulusMinusOne;
            var sharedSecret = baseClientSide.ModExp(exponent, modulus);
            var clientEphemeralBytes = ToBytes(ephemeral, bitLength);
            var sharedSecretBytes = ToBytes(sharedSecret, bitLength);
            var clientProof = ExpandHash(Concat(clientEphemeralBytes, serverEphemeralBytes, sharedSecretBytes));
            var serverProof = ExpandHash(Concat(clientEphemeralBytes, clientProof, sharedSecretBytes));

            return new Proofs(clientEphemeralBytes, clientProof, serverProof);
        }

        internal static BigInteger ToBigInteger(byte[] bytes)
        {
            // Append a zero byte to make sure the number is positive
            return new BigInteger(bytes.Append((byte)0).ToArray());
        }

        internal static byte[] ToBytes(BigInteger n)
        {
            var bytes = n.ToByteArray();
            return bytes[bytes.Length - 1] == 0 ? bytes.Sub(0, bytes.Length - 1) : bytes;
        }

        internal static byte[] ToBytes(BigInteger n, int bitLength)
        {
            var original = ToBytes(n);
            var byteLength = bitLength / 8;

            if (original.Length < byteLength)
                return Concat(original, new byte[byteLength - original.Length]);

            if (original.Length > byteLength)
                return original.Sub(0, byteLength);

            return original;
        }

        internal static BigInteger GetRandomBigInteger(BigInteger minValue, BigInteger maxValue)
        {
            if (minValue >= maxValue)
                throw new ArgumentException("minValue must be less than maxValue");

            var range = maxValue - minValue;
            var length = range.ToByteArray().Length;
            BigInteger result;

            do
            {
                var bytes = Crypto.RandomBytes(length);
                bytes[length - 1] &= 0x7F; // Ensure positive result
                result = new BigInteger(bytes);
            } while (result >= range);

            return result + minValue;
        }

        internal static byte[] ParseModulus(string message)
        {
            const string startToken = "-----BEGIN PGP SIGNED MESSAGE-----";
            const string endToken = "-----BEGIN PGP SIGNATURE-----";

            var startIndex = message.IndexOf(startToken, StringComparison.Ordinal);
            var endIndex = message.IndexOf(endToken, StringComparison.Ordinal);
            if (startIndex == -1 || endIndex == -1 || endIndex <= startIndex)
                throw new InternalErrorException("Invalid PGP message format: missing start or end token");

            startIndex = message.IndexOf("\n\n", startIndex, endIndex - startIndex, StringComparison.Ordinal);
            if (startIndex == -1)
                throw new InternalErrorException("Invalid PGP message format: missing two blank lines before message");

            // Skip \n\n
            startIndex += 2;

            return message.Substring(startIndex, endIndex - startIndex).Trim().Decode64();
        }

        internal static byte[] HashPassword(int version, string password, string username, byte[] salt, byte[] modulus)
        {
            var hash = version switch
            {
                0 => HashPasswordVersion0(password, username),
                1 => HashPasswordVersion1(password, username),
                2 => HashPasswordVersion2(password, username),
                3 or 4 => HashPasswordVersion3(password, salt),
                _ => throw new InternalErrorException($"Unsupported SRP version: {version}"),
            };

            return ExpandHash(Concat(hash, modulus));
        }

        internal static byte[] HashPasswordVersion0(string password, string username)
        {
            var usernamePassword = (username.ToLower() + password).ToBytes();
            var sha512 = Crypto.Sha512(usernamePassword);
            return HashPasswordVersion1(sha512.ToBase64(), username);
        }

        internal static byte[] HashPasswordVersion1(string password, string username)
        {
            var salt = Crypto.Md5(username.ToLower()).ToHex();
            var hashed = BCryptHashPassword(password, salt);
            return FixBCryptHash(hashed, salt).ToBytes();
        }

        internal static byte[] HashPasswordVersion2(string password, string username)
        {
            return HashPasswordVersion1(password, SanitizeUsername(username));
        }

        internal static byte[] HashPasswordVersion3(string password, byte[] salt)
        {
            var bcryptSalt = EncodeBase64(Concat(salt, "proton".ToBytes()), 16);
            return BCryptHashPassword(password, bcryptSalt).ToBytes();
        }

        internal static string BCryptHashPassword(string password, string salt)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCryptSaltHeader + salt);
        }

        // It appears that when BCrypt internally parses the salt parameter it trims it to 22 characters and then
        // does base64 decoding. When the result is calculated it is encoded back to base64 and because it was trimmed
        // at a weird border sometimes the re-encoded value is different in the last character. The pm-srp library
        // does it differently. They insert the original salt substring without re-encoding it, so it always matches
        // the input salt parameter. Here we replace the salt part of the hash with the original salt.
        internal static string FixBCryptHash(string hash, string salt)
        {
            if (hash.Length != 60)
                throw new InternalErrorException($"Invalid bcrypt hash: expected length 60, got {hash.Length}");

            if (!hash.StartsWith(BCryptSaltHeader))
                throw new InternalErrorException("Invalid bcrypt hash: missing version and cost");

            return BCryptSaltHeader + salt.Substring(0, 22) + hash.Substring(7 + 22);
        }

        internal static string SanitizeUsername(string username)
        {
            return username.Replace("-", "").Replace(".", "").Replace("_", "");
        }

        internal static byte[] ExpandHash(byte[] hash)
        {
            var expanded = new byte[64 * 4];

            var toHash = new byte[hash.Length + 1];
            hash.CopyTo(toHash, 0);

            for (var i = 0; i < 4; i++)
            {
                toHash[toHash.Length - 1] = (byte)i;
                Crypto.Sha512(toHash).CopyTo(expanded, i * 64);
            }

            return expanded;
        }

        // TODO: Move to Common
        // This code is adapted from https://github.com/BcryptNet/bcrypt.net/blob/main/src/BCrypt.Net/BCrypt.cs
        internal static string EncodeBase64(byte[] byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
                throw new ArgumentException("Invalid length", nameof(length));

            var encodedSize = (length * 4 + 2) / 3;
            var encoded = new char[encodedSize];

            var pos = 0;
            var off = 0;
            while (off < length)
            {
                var c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                var c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }

            return new string(encoded);
        }

        // TODO: Move to Common (could be turned into an extension method)
        internal static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }

        // TODO: Move to Common (could be turned into an extension method)
        internal static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            var result = new byte[a.Length + b.Length + c.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }

        //
        // Data
        //

        internal const int BitLength = 2048;

        private const string BCryptSaltHeader = "$2y$10$";

        private static readonly char[] Base64Code =
        {
            '.',
            '/',
            'A',
            'B',
            'C',
            'D',
            'E',
            'F',
            'G',
            'H',
            'I',
            'J',
            'K',
            'L',
            'M',
            'N',
            'O',
            'P',
            'Q',
            'R',
            'S',
            'T',
            'U',
            'V',
            'W',
            'X',
            'Y',
            'Z',
            'a',
            'b',
            'c',
            'd',
            'e',
            'f',
            'g',
            'h',
            'i',
            'j',
            'k',
            'l',
            'm',
            'n',
            'o',
            'p',
            'q',
            'r',
            's',
            't',
            'u',
            'v',
            'w',
            'x',
            'y',
            'z',
            '0',
            '1',
            '2',
            '3',
            '4',
            '5',
            '6',
            '7',
            '8',
            '9',
        };
    }
}
