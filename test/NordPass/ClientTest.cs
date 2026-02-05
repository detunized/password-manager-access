// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.NordPass;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.NordPass;

public class ClientTest
{
    [Fact]
    public void DecryptIdentityKey_returns_ed25519_keypair()
    {
        // Arrange
        var masterKey = MasterKey.Decode64();
        var encryptedPrivateKey = EncryptedIdentityPrivateKey.Decode64();

        // Act
        var ed25519Key = Client.DecryptIdentityKey(masterKey, encryptedPrivateKey);

        // Assert
        ed25519Key.Length.ShouldBe(64);
        ed25519Key.ShouldBe(Ed25519SecretKey.Decode64());
    }

    //
    // Data
    //

    private const string MasterKey = "wn/y0bj/U3y6rIguIWbCzUIisU8c+DYgIW65qvjwFWE=";
    private const string EncryptedIdentityPrivateKey =
        "nLGaxSYRDyv0FAJN1/72CMkecGqRLXzjshj89er3huZCwrYt68qqCUlEJv7xU9xsg5JdWUarma7OLZ5UpAwQc9bV9BnGnoYPMJYfrR2kaOxtknRupZ6q59iqbbkTLhNT0t535Sj3p8p4bkuc8OLz3k6ME/2HtqR2iCT7dbbYAZw=";
    private const string Ed25519SecretKey = "ztjjSrsP4Urdti2v4dZCCEApFhec9eL+TPspdKzBJ5lYBm4HWpOWRSJNXpVsdDr1kDjd4Ts9O7rUoKzwGOlj9g==";
}
