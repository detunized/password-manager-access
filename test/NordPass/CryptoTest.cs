// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;
using Crypto = PasswordManagerAccess.NordPass.Crypto;

namespace PasswordManagerAccess.Test.NordPass;

public class CryptoTest
{
    [Fact]
    public void DeriveKey_returns_derived_key()
    {
        // Arrange
        var salt = Salt.Decode64();

        // Act
        var key = Crypto.DeriveKey(MasterPassword, salt);

        // Assert
        key.ShouldBe(MasterKey.Decode64());
    }

    [Fact]
    public void DecryptXChaCha20Poly1305_decrypts_identity_key()
    {
        // Arrange
        var ciphertext = EncryptedIdentityPrivateKey.Decode64();
        var key = MasterKey.Decode64();

        // Act
        var plaintext = Crypto.DecryptXChaCha20Poly1305(ciphertext, key);

        // Assert
        plaintext.ShouldBe(DecryptedIdentityKey.Decode64());
    }

    [Fact]
    public void DecryptXChaCha20Poly1305_throws_on_short_ciphertext()
    {
        // Arrange
        var ciphertext = new byte[39];
        var key = new byte[32];

        // Act/Assert
        Should.Throw<InternalErrorException>(() => Crypto.DecryptXChaCha20Poly1305(ciphertext, key));
    }

    [Fact]
    public void DecryptSealedBox_decrypts()
    {
        // Arrange
        var ciphertext = SealedBoxCiphertext.Decode64();
        var publicKey = SealedBoxPublicKey.Decode64();
        var privateKey = SealedBoxPrivateKey.Decode64();

        // Act
        var plaintext = Crypto.DecryptSealedBox(ciphertext, publicKey, privateKey);

        // Assert
        plaintext.ShouldBe(SealedBoxPlaintext.Decode64());
    }

    [Fact]
    public void DecryptSealedBox_decrypts_item_key()
    {
        // Arrange
        var ciphertext = EncryptedItemPrivateKey.Decode64();
        var publicKey = X25519PublicKey.Decode64();
        var privateKey = X25519PrivateKey.Decode64();

        // Act
        var plaintext = Crypto.DecryptSealedBox(ciphertext, publicKey, privateKey);

        // Assert
        plaintext.ShouldBe(DecryptedItemPrivateKey.Decode64());
    }

    [Fact]
    public void Ed25519ToX25519Private_converts_key()
    {
        // Arrange
        var ed25519 = Ed25519SecretKey.Decode64();

        // Act
        var x25519 = Crypto.Ed25519ToX25519Private(ed25519);

        // Assert
        x25519.ShouldBe(X25519PrivateKey.Decode64());
    }

    [Fact]
    public void Ed25519ToX25519Public_converts_key()
    {
        // Arrange
        var ed25519 = Ed25519PublicKey.Decode64();

        // Act
        var x25519 = Crypto.Ed25519ToX25519Public(ed25519);

        // Assert
        x25519.ShouldBe(X25519PublicKey.Decode64());
    }

    //
    // Data
    //

    // Master password and derived key
    private const string MasterPassword = "what's a master password?";
    private const string Salt = "myZoJ8Uaw/OuACsyBWYxzw==";
    private const string MasterKey = "wn/y0bj/U3y6rIguIWbCzUIisU8c+DYgIW65qvjwFWE=";

    // Identity key encryption/decryption (XChaCha20-Poly1305, nonce prepended)
    private const string EncryptedIdentityPrivateKey =
        "nLGaxSYRDyv0FAJN1/72CMkecGqRLXzjshj89er3huZCwrYt68qqCUlEJv7xU9xsg5JdWUarma7OLZ5UpAwQc9bV9BnGnoYPMJYfrR2kaOxtknRupZ6q59iqbbkTLhNT0t535Sj3p8p4bkuc8OLz3k6ME/2HtqR2iCT7dbbYAZw=";
    private const string DecryptedIdentityKey =
        "enRqalNyc1A0VXJkdGkydjRkWkNDRUFwRmhlYzllTCtUUHNwZEt6Qko1bFlCbTRIV3BPV1JTSk5YcFZzZERyMWtEamQ0VHM5TzdyVW9LendHT2xqOWc9PQ==";

    // Ed25519 -> X25519 key conversion (from the real vault identity key)
    private const string Ed25519SecretKey = "ztjjSrsP4Urdti2v4dZCCEApFhec9eL+TPspdKzBJ5lYBm4HWpOWRSJNXpVsdDr1kDjd4Ts9O7rUoKzwGOlj9g==";
    private const string Ed25519PublicKey = "WAZuB1qTlkUiTV6VbHQ69ZA43eE7PTu61KCs8BjpY/Y=";
    private const string X25519PrivateKey = "EJnaD+q2OpTf67LcufA8A1DnG6chycOtVAfpoREnlnY=";
    private const string X25519PublicKey = "HilP+ma8Gin9BkJWyRHwqqCQUAB6zDqKqkUi5yuZUA4=";

    // Sealed box test vector (generated with libsodium)
    private const string SealedBoxPublicKey = "6q+b++MhuYs/FEtFZKiOx2E5eeU3j2L4K1OJ+Wr/JCw=";
    private const string SealedBoxPrivateKey = "yMtD86WxvzTsh8a3e0sdu1HyOFxCyOV5psJcsBMQmeI=";
    private const string SealedBoxCiphertext = "vJtD1H7F4tk8LQij1WYkaRbk6XJzlffHASzh1WD8qAvv8gPheWgCafBYyVWmy0r55WOFezj6G97vZjXNYPlCDg==";
    private const string SealedBoxPlaintext = "SGVsbG8sIE5vcmRQYXNzIQ=="; // "Hello, NordPass!"

    // Sealed box with real vault data (item key decryption)
    private const string EncryptedItemPrivateKey =
        "vrcggxlwgRqy33z6M4clgZA0ZekeDCGgKDscncS7mUZyR08zzduGJD062dwFwX9iMgI9g49oZtUVX2LFANrvkflLD7tve2F6VTyAVd20L6fuv6WQT+dCZ1i3wpMDoI8IMhXrFUdN6RJBaNqoh5TrhDvzCu2oFe57Rqla76bKW8BXslWTzYJMWQ==";
    private const string DecryptedItemPrivateKey =
        "S0l0UWFPVGtRYjZua2JXYkZGNU1XUmtWcy8ySHRZVzJLUlozMHV4M3FSVFIwRlc5WTh2MW8vTlcyd25HMnVkNFoyb0d3NU5JMER6S1lNbU9qMFZPaFE9PQ==";
}
