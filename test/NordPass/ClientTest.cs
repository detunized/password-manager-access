// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.NordPass;
using Shouldly;
using Xunit;
using Crypto = PasswordManagerAccess.NordPass.Crypto;

namespace PasswordManagerAccess.Test.NordPass;

public class ClientTest : TestBase
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
        json.ShouldContain("""type":"password""");
    }

    [Fact]
    public void DeriveKey_from_password_matches_expected_master_key()
    {
        // Arrange
        var vault = JsonSerializer.Deserialize<Model.Vault>(GetFixture("vault"))!;
        var salt = vault.Identities[0].Keys[0].Salt.Decode64();

        // Act
        var masterKey = Crypto.DeriveKey(MasterPassword, salt);

        // Assert
        masterKey.ShouldBe(MasterKey.Decode64());
    }

    [Fact]
    public void DecryptVault_decrypts_all_items()
    {
        // Arrange
        var fixture = JsonSerializer.Deserialize<Model.Vault>(GetFixture("vault"))!;

        // Act
        var vault = Client.DecryptVault(MasterPassword, fixture.Identities[0].Keys[0], fixture.VaultItems);

        // Assert
        vault.Accounts.Length.ShouldBe(6);

        var blah = vault.Accounts.First(a => a.Name == "Blah!");
        blah.Username.ShouldBe("blah");
        blah.Password.ShouldBe("blah blah");
        blah.Url.ShouldBe("https://blah.com");
        blah.Note.ShouldBe("blah blah blah");

        var minimal = vault.Accounts.First(a => a.Name == "Minimal Entry");
        minimal.Username.ShouldBe("minuser");
        minimal.Password.ShouldBe("minpass123");
        minimal.Url.ShouldBe("https://minimal.example.com");
    }

    //
    // OpenVault
    //

    [Fact]
    public async Task OpenVault_with_valid_access_token_skips_oauth()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: true, refreshTokenValid: true);
        var flow = new RestFlow { UseSystemJson = true }
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_with_expired_access_token_and_valid_refresh_token_refreshes()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: false, refreshTokenValid: true);
        var flow = new RestFlow { UseSystemJson = true }
            .Post(GetFixture("oauth-token")) // refresh
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_with_expired_access_token_and_failed_refresh_falls_through_to_oauth()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: false, refreshTokenValid: true);
        var flow = new RestFlow { UseSystemJson = true }
            .Post("", HttpStatusCode.Unauthorized) // refresh fails
            .Get("", HttpStatusCode.Unauthorized) // GetVault after failed refresh returns 401
            .Post(GetFixture("oauth-login")) // full OAuth
            .Post(GetFixture("oauth-token"))
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_with_valid_access_token_rejected_by_server_tries_refresh()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: true, refreshTokenValid: true);
        var flow = new RestFlow { UseSystemJson = true }
            .Get("", HttpStatusCode.Unauthorized) // access token rejected
            .Post(GetFixture("oauth-token")) // refresh succeeds
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_with_no_stored_auth_does_full_oauth()
    {
        // Arrange
        var storage = new MemoryStorage();
        var flow = new RestFlow { UseSystemJson = true }
            .Post(GetFixture("oauth-login"))
            .Post(GetFixture("oauth-token"))
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_with_no_stored_auth_stores_tokens_after_oauth()
    {
        // Arrange
        var storage = new MemoryStorage();
        var flow = new RestFlow { UseSystemJson = true }
            .Post(GetFixture("oauth-login"))
            .Post(GetFixture("oauth-token"))
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        storage.Values.ShouldContainKey("auth");
    }

    [Fact]
    public async Task OpenVault_with_all_tokens_expired_does_full_oauth()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: false, refreshTokenValid: false);
        var flow = new RestFlow { UseSystemJson = true }
            .Post(GetFixture("oauth-login"))
            .Post(GetFixture("oauth-token"))
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    [Fact]
    public async Task OpenVault_throws_when_user_cancels_oauth()
    {
        // Arrange
        var storage = new MemoryStorage();
        var flow = new RestFlow { UseSystemJson = true }.Post(GetFixture("oauth-login"));

        // Act/Assert
        await Should.ThrowAsync<CanceledMultiFactorException>(
            () => Client.OpenVault(Email, MasterPassword, new CancelUi(), storage, flow, CancellationToken.None)
        );
    }

    [Fact]
    public async Task OpenVault_with_valid_access_token_rejected_and_refresh_rejected_falls_through_to_oauth()
    {
        // Arrange
        var storage = await MakeStorageWithAuth(accessTokenValid: true, refreshTokenValid: true);
        var flow = new RestFlow { UseSystemJson = true }
            .Get("", HttpStatusCode.Unauthorized) // access token rejected
            .Post("", HttpStatusCode.Unauthorized) // refresh also fails
            .Get("", HttpStatusCode.Unauthorized) // GetVault after failed refresh returns 401
            .Post(GetFixture("oauth-login")) // full OAuth
            .Post(GetFixture("oauth-token"))
            .Get(GetFixture("identities"))
            .Get(GetFixture("vault-items-page-1"))
            .Get(GetFixture("vault-items-page-2"));

        // Act
        var vault = await Client.OpenVault(Email, MasterPassword, new SuccessUi(), storage, flow, CancellationToken.None);

        // Assert
        vault.Accounts.Length.ShouldBe(6);
    }

    //
    // FetchIdentities
    //

    [Fact]
    public async Task FetchIdentities_returns_parsed_identities()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }
            .Get(GetFixture("identities"))
            .ExpectUrl("v2/users/identities");

        // Act
        var identities = await Client.FetchIdentities(rest, CancellationToken.None);

        // Assert
        identities.Length.ShouldBe(1);
        identities[0].IdentityId.ShouldBe("2420f5f3-042c-491f-afcd-194414d12c71");
        identities[0].UserId.ShouldBe(30547275);
        identities[0].Keys.Length.ShouldBe(1);
        identities[0].Keys[0].IdentityKeyId.ShouldBe("86a5fc6f-1b4d-4b0e-b34e-c09574cc0bb9");
        identities[0].Keys[0].Salt.ShouldBe("myZoJ8Uaw/OuACsyBWYxzw==");
    }

    [Fact]
    public async Task FetchIdentities_throws_on_http_error()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }.Get("", HttpStatusCode.InternalServerError);

        // Act/Assert
        await Should.ThrowAsync<InternalErrorException>(() => Client.FetchIdentities(rest, CancellationToken.None));
    }

    [Fact]
    public async Task FetchIdentities_throws_TokenExpiredException_on_401()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }.Get("", HttpStatusCode.Unauthorized);

        // Act/Assert
        await Should.ThrowAsync<Client.TokenExpiredException>(() => Client.FetchIdentities(rest, CancellationToken.None));
    }

    //
    // FetchVaultItems
    //

    [Fact]
    public async Task FetchVaultItems_returns_parsed_items()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }
            .Get(GetFixture("vault-items-page-1"))
            .ExpectUrl("v2/users/identities/items")
            .ExpectUrl("identity_id=" + IdentityId)
            .ExpectUrl("page=1")
            .Get(GetFixture("vault-items-page-2"))
            .ExpectUrl("page=2");

        // Act
        var items = await Client.FetchVaultItems(IdentityId, rest, CancellationToken.None);

        // Assert
        items.Length.ShouldBe(11);
        items.Count(i => i.Type == "folder").ShouldBe(4);
        items.Count(i => i.Type == "item").ShouldBe(6);
        items.Count(i => i.Type == "option").ShouldBe(1);
    }

    [Fact]
    public async Task FetchVaultItems_throws_on_http_error()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }.Get("", HttpStatusCode.InternalServerError);

        // Act/Assert
        await Should.ThrowAsync<InternalErrorException>(() => Client.FetchVaultItems(IdentityId, rest, CancellationToken.None));
    }

    [Fact]
    public async Task FetchVaultItems_throws_TokenExpiredException_on_401()
    {
        // Arrange
        var rest = new RestFlow { UseSystemJson = true }.Get("", HttpStatusCode.Unauthorized);

        // Act/Assert
        await Should.ThrowAsync<Client.TokenExpiredException>(() => Client.FetchVaultItems(IdentityId, rest, CancellationToken.None));
    }

    //
    // ParseNordPassDateTime
    //

    [Theory]
    [InlineData("2026-02-21 13:58:17", 2026, 2, 21, 13, 58, 17)]
    [InlineData("2000-01-01 00:00:00", 2000, 1, 1, 0, 0, 0)]
    [InlineData("2099-12-31 23:59:59", 2099, 12, 31, 23, 59, 59)]
    public void ParseNordPassDateTime_parses_valid_date(string input, int year, int month, int day, int hour, int minute, int second)
    {
        // Act
        var result = Client.ParseNordPassDateTime(input);

        // Assert
        result.ShouldBe(new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc));
        result.Kind.ShouldBe(DateTimeKind.Utc);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-date")]
    [InlineData("2026-02-21")]
    [InlineData("2026-02-21T13:58:17")]
    [InlineData("21/02/2026 13:58:17")]
    public void ParseNordPassDateTime_throws_on_invalid_input(string input)
    {
        // Act/Assert
        Should.Throw<InternalErrorException>(() => Client.ParseNordPassDateTime(input));
    }

    //
    // Helpers
    //

    private const string Email = "test@example.com";

    private static async Task<MemoryStorage> MakeStorageWithAuth(bool accessTokenValid, bool refreshTokenValid)
    {
        var storage = new MemoryStorage();
        var now = DateTime.UtcNow;
        var auth = new
        {
            accessToken = "access-token",
            expiresAt = accessTokenValid ? now.AddHours(1) : now.AddHours(-1),
            refreshToken = "refresh-token",
            refreshExpiresAt = refreshTokenValid ? now.AddDays(30) : now.AddDays(-1),
        };
        await ((IAsyncSecureStorage)storage).StoreString("auth", JsonSerializer.Serialize(auth), CancellationToken.None);
        return storage;
    }

    private class SuccessUi : IAsyncUi
    {
        public Task<string?> AuthorizeOAuth(string url, CancellationToken cancellationToken) => Task.FromResult<string?>("verify-token");
    }

    private class CancelUi : IAsyncUi
    {
        public Task<string?> AuthorizeOAuth(string url, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
    }

    //
    // Data
    //

    private const string IdentityId = "2420f5f3-042c-491f-afcd-194414d12c71";
    private const string MasterPassword = "what's a master password?";
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
