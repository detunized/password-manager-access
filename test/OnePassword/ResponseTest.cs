// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;
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
    }
}
