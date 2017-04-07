// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        //
        // JToken
        //

        [Test]
        public void JToken_chained_At_returns_token()
        {
            var j = JObject.Parse(@"{
                'k1': {'k2': {'k3': 'v3'}}
            }");

            var k1 = j["k1"];
            var k2 = j["k1"]["k2"];
            var k3 = j["k1"]["k2"]["k3"];

            Assert.That(j.At("k1"), Is.EqualTo(k1));
            Assert.That(j.At("k1").At("k2"), Is.EqualTo(k2));
            Assert.That(j.At("k1").At("k2").At("k3"), Is.EqualTo(k3));

            Assert.That(j.At("k1").At("k2/k3"), Is.EqualTo(k3));
            Assert.That(j.At("k1/k2").At("k3"), Is.EqualTo(k3));
        }

        [Test]
        public void JToken_At_is_case_insensitive()
        {
            var j = JObject.Parse(@"{
                'keyOne': {'keyTwo': {'keyThree': 'v3'}}
            }");

            var k1 = j["keyOne"];
            var k2 = j["keyOne"]["keyTwo"];
            var k3 = j["keyOne"]["keyTwo"]["keyThree"];

            Assert.That(j.At("KEYone"), Is.EqualTo(k1));
            Assert.That(j.At("keyONE").At("KEYtwo"), Is.EqualTo(k2));
            Assert.That(j.At("KEyonE").At("keyTWO").At("KEYthree"), Is.EqualTo(k3));

            Assert.That(j.At("keyone").At("KEYTWO/kEYtHREE"), Is.EqualTo(k3));
            Assert.That(j.At("KEYONE/keytwo").At("KeyThree"), Is.EqualTo(k3));
            Assert.That(j.At("keyone/KEYTWO/keyTHREE"), Is.EqualTo(k3));
        }

        [Test]
        public void JToken_At_throws_on_invalid_path()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            Assert.That(() => j.At("i1"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k1/k11"), Throws.TypeOf<ArgumentException>());

            Assert.That(() => j.At("k2/i2"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k2/k22/i22"), Throws.TypeOf<ArgumentException>());

            Assert.That(() => j.At("k3/i3"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k3/k33/i33"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k3/k33/k333/i333"), Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void JToken_AtOrNull_returns_null_on_invalid_path()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            Assert.That(j.AtOrNull("i1"), Is.Null);
            Assert.That(j.AtOrNull("k1/k11"), Is.Null);

            Assert.That(j.AtOrNull("k2/i2"), Is.Null);
            Assert.That(j.AtOrNull("k2/k22/i22"), Is.Null);

            Assert.That(j.AtOrNull("k3/i3"), Is.Null);
            Assert.That(j.AtOrNull("k3/k33/i33"), Is.Null);
            Assert.That(j.AtOrNull("k3/k33/k333/i333"), Is.Null);
        }

        [Test]
        public void JToken_At_throws_on_non_objects()
        {
            var j = JObject.Parse(@"{
                'k1': [],
                'k2': true,
                'k3': 10
            }");

            Assert.That(() => j.At("k1/0"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k2/k22"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.At("k3/k33/k333"), Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void JToken_AtOrNull_returns_null_on_non_objects()
        {
            var j = JObject.Parse(@"{
                'k1': [],
                'k2': true,
                'k3': 10
            }");

            Assert.That(j.AtOrNull("k1/0"), Is.Null);
            Assert.That(j.AtOrNull("k2/k22"), Is.Null);
            Assert.That(j.AtOrNull("k3/k33/k333"), Is.Null);
        }

        [Test]
        public void JToken_StringAt_returns_string()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            Assert.That(j.StringAt("k1"), Is.EqualTo("v1"));
            Assert.That(j.StringAt("k2/k22"), Is.EqualTo("v22"));
            Assert.That(j.StringAt("k3/k33/k333"), Is.EqualTo("v333"));
        }

        [Test]
        public void JToken_StringAt_throws_on_non_stings()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': 10,
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            Assert.That(() => j.StringAt("k1"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.StringAt("k2"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.StringAt("k3"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.StringAt("k4"), Throws.TypeOf<ArgumentException>());
            Assert.That(() => j.StringAt("k5"), Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void JToken_StringAtOrNull_returns_null_on_non_stings()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': 10,
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            Assert.That(j.StringAtOrNull("k1"), Is.Null);
            Assert.That(j.StringAtOrNull("k2"), Is.Null);
            Assert.That(j.StringAtOrNull("k3"), Is.Null);
            Assert.That(j.StringAtOrNull("k4"), Is.Null);
            Assert.That(j.StringAtOrNull("k5"), Is.Null);
        }
    }
}
