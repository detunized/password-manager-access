// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json;
using PasswordManagerAccess.OnePassword;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ResponseTest : TestBase
    {
        [Fact]
        public void VaultItemDetails_parses_with_all_types_of_fields()
        {
            var json = GetFixture("vault-item-with-lots-of-fields");
            var details = JsonConvert.DeserializeObject<R.VaultItemDetails>(json);
            Assert.Equal(2, details.Sections.Length);
            Assert.Equal(6, details.Sections[0].Fields.Length);
            Assert.Equal(6, details.Sections[1].Fields.Length);
        }

        [Fact]
        public void VaultItem_parses_createdAt_and_updatedAt()
        {
            var json = GetFixture("get-vault-item-response");
            var response = JsonConvert.DeserializeObject<R.SingleVaultItem>(json);
            Assert.Equal("2016-08-04T13:15:10Z", response.Item.CreatedAt);
            Assert.Equal("2016-08-04T13:16:07Z", response.Item.UpdatedAt);
        }

        [Fact]
        public void VaultItem_handles_missing_createdAt_and_updatedAt()
        {
            var json = @"{
                ""uuid"": ""test-id"",
                ""templateUuid"": ""001"",
                ""trashed"": ""N"",
                ""itemVersion"": 1,
                ""encryptedBy"": ""test-key"",
                ""encOverview"": {
                    ""kid"": ""test-key"",
                    ""enc"": ""A256GCM"",
                    ""cty"": ""b5+jwk+json"",
                    ""iv"": ""test-iv"",
                    ""data"": ""test-data""
                },
                ""encDetails"": {
                    ""kid"": ""test-key"",
                    ""enc"": ""A256GCM"",
                    ""cty"": ""b5+jwk+json"",
                    ""iv"": ""test-iv"",
                    ""data"": ""test-data""
                }
            }";
            var item = JsonConvert.DeserializeObject<R.VaultItem>(json);
            Assert.Null(item.CreatedAt);
            Assert.Null(item.UpdatedAt);
        }

        [Fact]
        public void VaultItem_handles_invalid_createdAt_and_updatedAt()
        {
            var json = @"{
                ""uuid"": ""test-id"",
                ""templateUuid"": ""001"",
                ""trashed"": ""N"",
                ""createdAt"": ""not-a-date"",
                ""updatedAt"": ""also-not-a-date"",
                ""itemVersion"": 1,
                ""encryptedBy"": ""test-key"",
                ""encOverview"": {
                    ""kid"": ""test-key"",
                    ""enc"": ""A256GCM"",
                    ""cty"": ""b5+jwk+json"",
                    ""iv"": ""test-iv"",
                    ""data"": ""test-data""
                },
                ""encDetails"": {
                    ""kid"": ""test-key"",
                    ""enc"": ""A256GCM"",
                    ""cty"": ""b5+jwk+json"",
                    ""iv"": ""test-iv"",
                    ""data"": ""test-data""
                }
            }";
            var item = JsonConvert.DeserializeObject<R.VaultItem>(json);
            Assert.Equal("not-a-date", item.CreatedAt);
            Assert.Equal("also-not-a-date", item.UpdatedAt);
        }

        [Fact]
        public void VaultItem_ParseDateTime_parses_valid_date()
        {
            var result = VaultItem.ParseDateTime("2016-08-04T13:15:10Z");
            Assert.Equal(new DateTime(2016, 8, 4, 13, 15, 10, DateTimeKind.Utc), result);
        }

        [Fact]
        public void VaultItem_ParseDateTime_returns_default_for_null()
        {
            var result = VaultItem.ParseDateTime(null);
            Assert.Equal(default(DateTime), result);
        }

        [Fact]
        public void VaultItem_ParseDateTime_returns_default_for_empty()
        {
            var result = VaultItem.ParseDateTime("");
            Assert.Equal(default(DateTime), result);
        }

        [Fact]
        public void VaultItem_ParseDateTime_returns_default_for_invalid()
        {
            var result = VaultItem.ParseDateTime("not-a-date");
            Assert.Equal(default(DateTime), result);
        }
    }
}
