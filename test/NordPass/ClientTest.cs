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

    [Fact]
    public void DecryptItemKey_returns_ed25519_keypair()
    {
        // Arrange
        var x25519Public = X25519PublicKey.Decode64();
        var x25519Private = X25519PrivateKey.Decode64();
        var encryptedItemKey = EncryptedItemPrivateKey.Decode64();

        // Act
        var ed25519Key = Client.DecryptItemKey(x25519Public, x25519Private, encryptedItemKey);

        // Assert
        ed25519Key.Length.ShouldBe(64);
        ed25519Key.ShouldBe(DecryptedItemEd25519Key.Decode64());
    }

    [Fact]
    public void DecryptValueKey_returns_symmetric_key()
    {
        // Arrange
        var itemX25519Public = ItemX25519PublicKey.Decode64();
        var itemX25519Private = ItemX25519PrivateKey.Decode64();
        var encryptedValueKey = EncryptedValueKey.Decode64();

        // Act
        var valueKey = Client.DecryptValueKey(itemX25519Public, itemX25519Private, encryptedValueKey);

        // Assert
        valueKey.Length.ShouldBe(32);
        valueKey.ShouldBe(DecryptedValueKey.Decode64());
    }

    [Fact]
    public void DecryptItemValue_returns_json_string()
    {
        // Arrange
        var valueKey = DecryptedValueKey.Decode64();
        var encryptedValue = EncryptedItemValue.Decode64();

        // Act
        var json = Client.DecryptItemValue(valueKey, encryptedValue);

        // Assert
        json.ShouldContain(""""type":"password"""");
    }

    //
    // Data
    //

    private const string MasterKey = "wn/y0bj/U3y6rIguIWbCzUIisU8c+DYgIW65qvjwFWE=";
    private const string EncryptedIdentityPrivateKey =
        "nLGaxSYRDyv0FAJN1/72CMkecGqRLXzjshj89er3huZCwrYt68qqCUlEJv7xU9xsg5JdWUarma7OLZ5UpAwQc9bV9BnGnoYPMJYfrR2kaOxtknRupZ6q59iqbbkTLhNT0t535Sj3p8p4bkuc8OLz3k6ME/2HtqR2iCT7dbbYAZw=";
    private const string Ed25519SecretKey = "ztjjSrsP4Urdti2v4dZCCEApFhec9eL+TPspdKzBJ5lYBm4HWpOWRSJNXpVsdDr1kDjd4Ts9O7rUoKzwGOlj9g==";

    // Identity X25519 keys (converted from Ed25519)
    private const string X25519PublicKey = "HilP+ma8Gin9BkJWyRHwqqCQUAB6zDqKqkUi5yuZUA4=";
    private const string X25519PrivateKey = "EJnaD+q2OpTf67LcufA8A1DnG6chycOtVAfpoREnlnY=";

    // "Blah!" item key
    private const string EncryptedItemPrivateKey =
        "vrcggxlwgRqy33z6M4clgZA0ZekeDCGgKDscncS7mUZyR08zzduGJD062dwFwX9iMgI9g49oZtUVX2LFANrvkflLD7tve2F6VTyAVd20L6fuv6WQT+dCZ1i3wpMDoI8IMhXrFUdN6RJBaNqoh5TrhDvzCu2oFe57Rqla76bKW8BXslWTzYJMWQ==";
    private const string DecryptedItemEd25519Key = "KItQaOTkQb6nkbWbFF5MWRkVs/2HtYW2KRZ30ux3qRTR0FW9Y8v1o/NW2wnG2ud4Z2oGw5NI0DzKYMmOj0VOhQ==";

    // "Blah!" item X25519 keys (converted from item Ed25519)
    private const string ItemX25519PublicKey = "lzMYzwLeVvi1ZRzz6y/b40ABvPHKgx+yDggrY7J/wiA=";
    private const string ItemX25519PrivateKey = "2GzuSpcVP61Wt2JTzPsDZbE9bICj93XYeX2JFfGG+V4=";

    // "Blah!" value key
    private const string EncryptedValueKey =
        "mop5ZftIzaBDmHKrXmzX2g0r9OGR7gkpc5dbC0CuqE4Jnfs/G0hyrs0RqH2ejYoidKWIU3iSUjvhy0hWBC2KKg+P/w1M4abIdj4iWujQr6STYC1OlU3TO/Rye9I=";
    private const string DecryptedValueKey = "VvodJAzhsCnPuPfz+oGhRttgC0ek89LgbL4SY9QJ2DY=";

    // "Blah!" encrypted item value
    private const string EncryptedItemValue =
        "VlrzZe9eMuWhJ1JfNly3nP4MIrQ7qwRLRnKHi/QRg4OnpAfWMVnGjofe/3Dw9/PS09S6E/vUaMo/zecBevK3/z2/9RnI85a19qHOD0joZZ6N1LHmMxouFr+oYG2r/T8UITjojp4R0iVuWadwH07hWC/TfjfWMgbs3sXzw0V9bzFEgUVkmabx5aLcrddhYZIXQpGDVr0mui6mvdpguAZd7wXH03Svmztq45akcsqzCa1CvtZ8Oy/6oltkkrxhnaCThR8kbdVlzNgxVO55P3KImkJuzplNSpXMsYvXszFO2UCwlq3e9inSbWIICskDAwtxjvr3tRCdCkSjBG8u4VjZYee2gTl5v8rRTI06GRU06gx6f6bKYywGRQDpRNPr4q7GWPPZ0ZgMqKag9pPsHMoSqa38i8D4B2gonkfecm2dhh7DGLduF5qIvpsOQcuXB80t9n/320gnqsu3Cyy+Jb+AHx605pGzQtKCX6uX1by9AchWMcy4QnWKtHKRFA3Ge8MU0gdp9RFDktER8dkpPOlXW70=";
}
