// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Runtime.CompilerServices;

namespace PasswordManagerAccess.Common
{
    // This is a port of https://github.com/golang/crypto/blob/master/poly1305/
    //
    // Poly1305 [RFC 7539] is a relatively simple algorithm: the authentication tag
    // for a 64 bytes message is approximately
    //
    //     s + m[0:16] * r^4 + m[16:32] * r^3 + m[32:48] * r^2 + m[48:64] * r  mod  2^130 - 5
    //
    // for some secret r and s. It can be computed sequentially like
    //
    //     for len(msg) > 0:
    //         h += read(msg, 16)
    //         h *= r
    //         h %= 2^130 - 5
    //     return h + s
    //
    // All the complexity is about doing performant constant-time math on numbers
    // larger than any available numeric type.
    internal struct Poly1305
    {
        public const int BlockSize = 16;

        // TODO: The `key` parameter should really be a ReadOnlySpan. The problem is with the
        //       Unsafe.ReadUnaligned function. It accepts a ref and not a readonly ref.
        public Poly1305(Span<byte> key)
        {
            _r0 = Unsafe.ReadUnaligned<ulong>(ref key[0]) & 0x0FFFFFFC0FFFFFFF;
            _r1 = Unsafe.ReadUnaligned<ulong>(ref key[8]) & 0x0FFFFFFC0FFFFFFC;

            _s0 = Unsafe.ReadUnaligned<ulong>(ref key[16]);
            _s1 = Unsafe.ReadUnaligned<ulong>(ref key[24]);

            _h0 = 0;
            _h1 = 0;
            _h2 = 0;
        }

        // Update splits the incoming message into BlockSize chunks. The original Go implementation
        // supports arbitrary length updates, but for our needs it's not necessary. So all the updates
        // must of length divisible by BlockSize or an exception is thrown.
        //
        // Update absorbs data into the state _h accumulator. For each chunk m of 128 bits of message,
        // it computes:
        //
        //     h = (h + m) * r  mod 2^130 - 5
        //
        // TODO: The `data` parameter should really be a ReadOnlySpan. The problem is with the
        //       Unsafe.ReadUnaligned function. It accepts a ref and not a readonly ref.
        public void Update(Span<byte> data)
        {
            // TODO: In theory Poly1305 should support arbitrary length updates. We only use it
            // in XChaCha20Poly1305 algorithm where all the updates are block aligned.
            if (data.Length % BlockSize != 0)
                throw new InternalErrorException("Only complete blocks updates are supported");

            int carry;

            ulong h0 = _h0;
            ulong h1 = _h1;
            ulong h2 = _h2;

            ulong r0 = _r0;
            ulong r1 = _r1;

            for (var offset = 0; offset < data.Length; offset += BlockSize)
            {
                // For the first step, h + m, we use a chain of AddWithCarry. The resulting value of h might
                // exceed 2^130 - 5, but will be partially reduced at the end of the multiplication below.
                //
                // The spec requires us to set a bit just above the message size, not to hide leading zeroes.
                // For full chunks, that's 1 << 128, so we can just add 1 to the most significant (2^128) limb, h2.
                (h0, carry) = AddWithCarry(h0, Unsafe.ReadUnaligned<ulong>(ref data[offset]), 0);
                (h1, carry) = AddWithCarry(h1, Unsafe.ReadUnaligned<ulong>(ref data[offset + 8]), carry);
                h2 += (ulong)(carry + 1);

                // Multiplication of big number limbs is similar to elementary school
                // columnar multiplication. Instead of digits, there are 64-bit limbs.
                //
                // We are multiplying a 3 limbs number, h, by a 2 limbs number, r.
                //
                //                        h2    h1    h0  x
                //                              r1    r0  =
                //                       ----------------
                //                      h2r0  h1r0  h0r0     <-- individual 128-bit products
                //            +   h2r1  h1r1  h0r1
                //               ------------------------
                //                 m3    m2    m1    m0      <-- result in 128-bit overlapping limbs
                //               ------------------------
                //         m3.hi m2.hi m1.hi m0.hi           <-- carry propagation
                //     +         m3.lo m2.lo m1.lo m0.lo
                //        -------------------------------
                //           t4    t3    t2    t1    t0      <-- final result in 64-bit limbs
                //
                // The main difference from pen-and-paper multiplication is that we do
                // carry propagation in a separate step, as if we wrote two digit sums
                // at first (the 128-bit limbs), and then carried the tens all at once.
                var h0r0 = Multiply(h0, r0);
                var h1r0 = Multiply(h1, r0);
                var h2r0 = Multiply(h2, r0);
                var h0r1 = Multiply(h0, r1);
                var h1r1 = Multiply(h1, r1);
                var h2r1 = Multiply(h2, r1);

                // Since h2 is known to be at most 7 (5 + 1 + 1), and r0 and r1 have their
                // top 4 bits cleared by the masks, we know that their product is not going
                // to overflow 64 bits, so we can ignore the high part of the products.
                // This also means that the product doesn't have a fifth limb (t4).

                var m0 = h0r0;
                var m1 = Add(h1r0, h0r1); // These two additions don't overflow thanks again
                var m2 = Add(h2r0, h1r1); // to the 4 masked bits at the top of r0 and r1.
                var m3 = h2r1;

                var t0 = m0.Lo;
                ulong t1;
                (t1, carry) = AddWithCarry(m1.Lo, m0.Hi, 0);
                ulong t2;
                (t2, carry) = AddWithCarry(m2.Lo, m1.Hi, carry);
                var (t3, _) = AddWithCarry(m3.Lo, m2.Hi, carry);

                // Now we have the result as 4 64-bit limbs, and we need to reduce it
                // modulo 2^130 - 5. The special shape of this Crandall prime lets us
                // do a cheap partial reduction according to the reduction identity:
                //
                //     c * 2^130 + n  =  c * 5 + n  mod  2^130 - 5
                //
                // because 2^130 = 5 mod 2^130 - 5. Partial reduction since the result is
                // likely to be larger than 2^130 - 5, but still small enough to fit the
                // assumptions we make about h in the rest of the code.
                //
                // See also https://speakerdeck.com/gtank/engineering-prime-numbers?slide=23

                // We split the final result at the 2^130 mark into h and cc, the carry.
                // Note that the carry bits are effectively shifted left by 2, in other
                // words, cc = c * 4 for the c in the reduction identity.

                h0 = t0;
                h1 = t1;
                h2 = t2 & 0x0000000000000003UL;
                var cc = new UInt128(t2 & ~0x0000000000000003UL, t3);

                // To add c * 5 to h, we first add cc = c * 4, and then add (cc >> 2) = c.

                (h0, carry) = AddWithCarry(h0, cc.Lo, 0);
                (h1, carry) = AddWithCarry(h1, cc.Hi, carry);
                h2 += (ulong)carry;

                cc.Lo = cc.Lo >> 2 | (cc.Hi & 3) << 62;
                cc.Hi >>= 2;

                (h0, carry) = AddWithCarry(h0, cc.Lo, 0);
                (h1, carry) = AddWithCarry(h1, cc.Hi, carry);
                h2 += (ulong)carry;

                // h2 is at most 3 + 1 + 1 = 5, making the whole of h at most
                //
                //     5 * 2^128 + (2^128 - 1) = 6 * 2^128 - 1
            }

            _h0 = h0;
            _h1 = h1;
            _h2 = h2;
        }

        // Finish generates the MAC output. Finish can be called multiple times. Calling
        // Update after Finish is not allowed (not enforced though).
        public void Finish(Span<byte> mac)
        {
            if (mac.Length != 16)
                throw new InternalErrorException("MAC should be exactly 16 bytes long");

            int borrow;
            int carry;

            ulong h0 = _h0;
            ulong h1 = _h1;
            ulong h2 = _h2;

            // After the partial reduction in Update, h might be more than 2^130 - 5,
            // but will be less than 2 * (2^130 - 5). To complete the reduction in
            // constant time, we compute t = h - (2^130 - 5), and select h as the
            // result if the subtraction underflows, and t otherwise.

            ulong hMinusP0;
            (hMinusP0, borrow) = SubtractWithBorrow(h0, 0xFFFFFFFFFFFFFFFB, 0);
            ulong hMinusP1;
            (hMinusP1, borrow) = SubtractWithBorrow(h1, 0xFFFFFFFFFFFFFFFF, borrow);
            (_, borrow) = SubtractWithBorrow(h2, 0x0000000000000003, borrow);

            // h = h if h < p else h - p
            h0 = Select(borrow, h0, hMinusP0);
            h1 = Select(borrow, h1, hMinusP1);

            // Finally, we compute the last Poly1305 step
            //
            //     tag = h + s  mod  2^128
            //
            // by just doing a wide addition with the 128 low bits of h and discarding
            // the overflow.
            (h0, carry) = AddWithCarry(h0, _s0, 0);
            (h1, _) = AddWithCarry(h1, _s1, carry);

            Unsafe.WriteUnaligned(ref mac[0], h0);
            Unsafe.WriteUnaligned(ref mac[8], h1);
        }

        //
        // Internal
        //

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static (ulong, int) AddWithCarry(ulong x, ulong y, int carry)
        {
            ulong sum = unchecked(x + y + (ulong)carry);
            return (sum, (int)(((x & y) | ((x | y) & ~sum)) >> 63));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static (ulong, int) SubtractWithBorrow(ulong x, ulong y, int borrow)
        {
            ulong diff = unchecked(x - y - (ulong)borrow);
            return (diff, (int)(((~x & y) | (~(x ^ y) & diff)) >> 63));
        }

        // TODO: Do we need this?
        // returns x if v == 1 and y if v == 0, in constant time.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong Select(int v, ulong x, ulong y)
        {
            return (ulong)~(v - 1) & x | (ulong)(v - 1) & y;
        }

        // TODO: See if this could be merged with PasswordManagerAccess.OnePassword.UInt128
        internal ref struct UInt128
        {
            public ulong Lo;
            public ulong Hi;

            public UInt128(ulong lo, ulong hi)
            {
                Lo = lo;
                Hi = hi;
            }
        }

        internal static UInt128 Add(UInt128 x, UInt128 y)
        {
            var (lo, carry) = AddWithCarry(x.Lo, y.Lo, 0);
            var (hi, _) = AddWithCarry(x.Hi, y.Hi, carry);
            return new UInt128(lo, hi);
        }

        internal static UInt128 Multiply(ulong x, ulong y)
        {
            const ulong mask32 = 0xFFFFFFFF;
            var x0 = x & mask32;
            var x1 = x >> 32;
            var y0 = y & mask32;
            var y1 = y >> 32;
            var w0 = x0 * y0;
            var t = x1 * y0 + (w0 >> 32);
            var w1 = t & mask32;
            var w2 = t >> 32;
            w1 += x0 * y1;

            return new UInt128(lo: x * y, hi: x1 * y1 + w2 + (w1 >> 32));
        }

        // State holds numbers in saturated 64-bit little-endian limbs. That is,
        // the value of [x0, x1, x2] is x[0] + x[1] * 2^64 + x[2] * 2^128.

        // h is the main accumulator. It is to be interpreted modulo 2^130 - 5, but
        // can grow larger during and after rounds. It must, however, remain below
        // 2 * (2^130 - 5).
        private ulong _h0,
            _h1,
            _h2;

        // r and s are the private key components.
        private readonly ulong _r0,
            _r1;
        private readonly ulong _s0,
            _s1;
    }
}
