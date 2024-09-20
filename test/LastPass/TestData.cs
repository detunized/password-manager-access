// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test.LastPass
{
    static class TestData
    {
        public static readonly string[] ChunkIds =
        {
            "LPAV",
            "PREM",
            "ENTU",
            "ENTM",
            "ENTA",
            "ATVR",
            "ENCU",
            "CBCU",
            "BBTE",
            "IPTE",
            "WMTE",
            "ANTE",
            "DOTE",
            "FETE",
            "FUTE",
            "SYTE",
            "WOTE",
            "TATE",
            "WPTE",
            "PRIK",
            "SPMT",
            "PREF",
            "NMAC",
            "ACCT",
            "NEVR",
            "SOSS",
            "EQDN",
            "URUL",
            "TOTP",
            "SHAR",
            "ENDM",
        };

        public static readonly byte[] EncryptionKey = "p8utF7ZB8yD06SrtrD4hsdvEOiBU1Y19cr2dhG9DWZg=".Decode64();

        public static readonly string EncryptedPrivateKey =
            "fc61ba57136d7ebb627e659a1e1f0ac6792da5bea14288900437c276a82df9137a391a7f6d4589477abace45533add96b5cc3bed"
            + "2d744aa4a4c8ff35986cd2af1533b87e04689805303f129ba1d5d6ad22466449408e350b6f15dce065a4026bd36495aae6f7220b"
            + "2b410ffdfe91064d4440327d3b759a093f125262d1d6dc00f9c2c6573875aef98ef466d2305009e81c637d2a8f378103e4ecb6ed"
            + "185efeeb636d5e4af52bf8ad39b393b672355573331831b424a9c1684f10d58fb7b5c84da5d2d0b31430d87ea9817a81857a4ea4"
            + "1a5f60c17d66f0eaa92ec73a643e8b3c0620601741466347d9a69405f02c37403b1b6d298ebd33a57db9900d3050b95d49d2705f"
            + "bb68ef5d0f8a6bff33f6654380d0877dc0cb1d1aa819cc2b39ebe89917f24f9bf7c5a074aca558e0eccbb3ad7477365a4c036f01"
            + "6e0af93260e92fd3060ba7b5ce9b530cef7c0cca1438b1a7728d701cb209a4bf2a2d153fb46441ecbc8ac563f1f7c0aa58dd0181"
            + "c641a3e7a3847f58b01523cd02b6a219d7ed7b54f445daa082832de4164e5227dc0e69e2ddaef1ccb957026de9e1dcfb1effaee3"
            + "e3f1a00939ec1a6998ea40e43495162a90689ddaf5dbbf91830f4849bbbc2314647898034544f8dcd1dd17c90c6ff724b6a7af62"
            + "910ceade55c7ba7947a838f9332fdbaef496745c16667b3f25dfae35d855f578b59dfb37676601e416374bd167722f0dbc6762a7"
            + "a512e4da5f1c88aaa7d7c274e84365c2362c6787dfd3e19eebd49d7ebe05b266e39d193d8b98f73dc293421953b1056c066ad585"
            + "e9f01b51e0195905e1456a92840f1ae0f1af1359620e923cc38b0430d27055ecde6a54b55c082093d5efa252e8d63e7acc40c328"
            + "ee9c03ff0d1e3d8bf7805a45dd98b57418a3caea7fe875022b5eb8bbaa17fc793f51a782695878f51bf5175ce29951193b04be1c"
            + "384bc3d49d8f9c22552f81f024dae925caf731a0538e119c40f9b4dfbbdc26b0867a0d2a8948b812ce95741cdfeeaaee3e47fcaf"
            + "1eaba954455d757e54ba2fa68b191d906ea7cd539b72b1da6bf640316e4402c5219309f31288e602e6d9c303c39a6badc378c475"
            + "b0b01ce6dd98dfcb03b5c3c53ab380e50b26021502246e5a1b0d9297386ac8f17ab370c2195090556696f29a1d0dbfd2464da6f2"
            + "5f6096e1430b697d2ecc2b0c13ebff3b43609dc35b8a3971bcb554fb49dc46d068a1a7766235aa4009905b57e6de4391696b711b"
            + "0de2b73341526ad6a4ac37626d938c7560a0e46112560076fcd5c144ec5388be5ac64fcd355987aca4d0297bd8025f28f79bd4eb"
            + "adb64f9fc77d3edd31c948d7255e986cbf033e743d52d1ae67fb221e72535f6bbcb2658ab03bd8e413eb4d4c80258741dd4b1306"
            + "b9779fc29433ff36dcb4777dabfcfb3eed605a30308ca5bb96728e16071def7c64307fc6ee7333733c766dfa2bec6c60a690fcf4"
            + "61197578547e65fe8bdf3478bce0458c522985b46dbc860269fa5351b444f3d39acd659af74de4660923ae91d92d9c75ca46977b"
            + "062f3aa2f686bb12f485e23cfd14e26df1e1e64dd8791b572cabb382c61dc221fa28d0599a1dd78b83365665d702cf8635d90931"
            + "8aeebf5f3793411abcf4916d7aac7d1fa430a9fefb5a7f3eb881d001e9fce1defadf7c252f458354758c06f636f9295f2f22b96a"
            + "2955edfc5b7604f1d89861abf40e7822aac43ae5145d2cd2757b8af967d57e400ae5d03ff55d3f9d083ae79f03d2cfbffaf0169f"
            + "45aaa500a480c9935c151166ed141b1fba1cb255e50d35abe8d90ed49bebc186649eb7f0831dc89a9f65369c60e56ac4228ddd10"
            + "cea05677e96eda91ff6c8e7821ff66418279e8a8f4c5adc3851ea0f9f104bff19e64df6e435c857a890f9f1fb837d0acea1b7c3e"
            + "242f60cb58d7a27e3c42eecd8bed832e058554731b69a3f9e7cff47f678f6b55931878aeaeb7de3fddf402251535ef7674c0915e"
            + "02e611a5c340c55fb249683a0be8904db861edaa222a4824bb0e5478123bca2b6d6a19418faae6e6d60f8c3f9070f095e7efbf40"
            + "1f110fdee5381bd2e7556c891bbe90d405186905e1178919a7383ec137ea78b5ac4d47a66046906b22fec8411c572b8b3c729b0a"
            + "c4392679f0b60065d68d0f01abf76a900b1eb60c007eebc1950cab598b64681deafdacde51d0fd51e530b7a8fd82ed4fe5f30ecc"
            + "66c622284976afe1895e80d9d730e8aac45755b971779cadec8cbd8c2921750c2aacd9ae6f6a3d14b00b218bbd82b2300686984e"
            + "8ec6f6771cd0c58117b5fe9ab1fe1d8a5aa26f81c34f2a3a146170bd35cf3148474859050c711335d6a186807bd89e8c29079145"
            + "769200183d4949976bc5eef5f205e87480ac283ae9473683228dbcc6c3ebfce22f6abb1e87a08e3a4b2071953bd5b21817eaf3f8"
            + "6cbd11fb7f793de529a13aa89a47bec616b5b1c38998a42226f667fdb394228f9ad1de050ed27caa3d0e93436872db8a2a23d673"
            + "42311eb3f1c6ad102853477bf03297eeb89d62c8012a9b48aef0003fc536c8b76706bd9cb46a7062a1efcc495331cc9edd5c3b10"
            + "c79252676b34599acf95b6200efa28571635dfc8a2823e6b5c0003430a2e1c76984a6b21cf55166eb7cd169a61e1a968cdd997f8"
            + "3e3dd3e0a81a0685c09d8eb55578ddeb27833bbe9dfaf2906b970678820aed2988babc4cce1cee294f247c5c1dfbefc4cd19fe1a"
            + "f936d9c22185e70ef7ea00f952fd5591f980a9a8e5755f4818b373a070d7ddedc6eadc9fd3d7838ec4fe5680e30444784bfb0710"
            + "175a52d962f61ff11de6d4c872e05f2e32bedfa62e975fe5cdee622d88babcedda0c19a4e738833e40e4ef658127e642cfa292fd"
            + "b6c1c1bd43c631c7202eeacd3a41682278e896f1f1338eac5a0ad075aa5e1657facaad4f25edee8f03c62a8976c0bdf4808ddfef"
            + "b8adf193aabc73a16e0d9504fc7c5e470815c1b352c954becf1e2e9d3dfec49cb7aa17c3ec9916de9d475801b8ab8c3217905883"
            + "40905e4adac6a8c5b5d515851a64f03a5d4da800e130053e1412283746a7b99ee905e1b3fcef5f5d08d3bc50eeb6cfa4c4997ab3"
            + "891b7058be08c67f1846267b97b7d6fd10c64c3015e44c006f74529388a1d31ec08a06571d857da2706aa32a30bd9d7e3b1b8b6a"
            + "3ac55cef6b9ff342f660b76e583bcfe99e23037acfdff1e8ed9a0abcc15cfe296197363a0fc68958a750a54d46bd8c11c683e70e"
            + "5e2bacb9e3d24220d9ec280495aecbb91f8e018323439c2edbd18a5759446e88ea7299fccc66af6d8deda32a0aef1a072c17b8c3"
            + "966f9279be6c5b75ca7fad586dcf7484459e3ab40d9ab9c8375e6de084a8e737d83171950e5cfbfb794979752f8a8a5b3d35eced"
            + "3c477ae405492260108bd72d23931e919d711f9719ab34384ed10bd7230e1c92413b8d89698e4440158fa9c59c9ef78df2291a1f"
            + "e84871e72d249c707a3ae02b1dedc1d41409353f258e5aea02cb37af3e9f6829bb465dd8";

        public static readonly byte[] RsaD = (
            "dXimo4YNfc8O2Mm234V/iiolY6vWOvk1Lt+CXMpcsc9CMedtg+pBVn4JyjUHSw5Rc/2RZcmEDcg0rWVNU3WbJVFo0b6yKwvrx4IlUA71"
            + "YOxnpAPNx+2ocNAVWg/5uxzhs92JtkwC544Nh9JF9e3RblMax9TQssUMAQ3Clqgcz8VG8JkYBUXicwTFgDkJnV+2emdwn5F7ABmepGEZ"
            + "UQNlvIU3ezNQJUfXUWITd4+rPZoohk30pdOvCTn0h4raFl0eP8ZEzNReIkZs8A2c9/6gzgSawMdgJU6IXoaG7fOYtMt0Rsp96+fqxmf2"
            + "jPj1S0j2TnGzR0KMC3lxhqIP8NLa+Q=="
        ).Decode64();

        public static readonly byte[] RsaDP = (
            "M56unlPmN6ymFx8wgOMbtLKQg65AM69sORfUcglFfi/6mk1Q2SWp5J4zcNuGucJHoPJ8mXwKeXlAKOzY3fvBI3/zt+fjui4ZR+Rwjv5D"
            + "4XTErz1srr6G7yDjCpvtHOJmMWNkmUGmdCrLe65cg5cEjxBBIV1Y0cRovF9bKuSuB6E="
        ).Decode64();

        public static readonly byte[] RsaDQ = (
            "fJ2pdUUbjfvPOn8DmzkTYCo7q9tFHWuE00Y5LKbvenPxDA55ImLU0YM4civve1ObI8E9l+ufwOIOAMI5v14GJAGwb0HE9o2ZodTIQouo"
            + "XmbP1GYnbQj6PmbvX+0rGx+vqeZf414CBlnAd4YjprlOA5Mm8lSWueCR9leUxKpdj+U="
        ).Decode64();

        public static readonly byte[] RsaExponent = "EQ==".Decode64();

        public static readonly byte[] RsaInverseQ = (
            "CDC3/yIrcTf1DGxQny7Jr1/mO+UQG/PeraOAZc99VonwGszLHuv/6O8UyyPp4QpzSNZbu5fpQ6qWE5zhXChP6xTL6bhkRfNzpgRu0aCJ"
            + "ANUGX2S9IsNmJLwvFEvocVP0WkVsLtszfUuWAMjF2Ah9pFl6CW6WCbwwPW7Ax6Q5uCA="
        ).Decode64();

        public static readonly byte[] RsaModulus = (
            "tYvqQolaqyi52qwan0Kt1Ybz9yDWuDtSMSrgvfLsWJ1mTR/Xy95k+giaxCNoXLkJhLZsV31AcmP0UcsaabXBOaxcLODkzimyNFTFTS5j"
            + "8uG3cddVTEC+f804RV6B8qD/uOIDX4y+q6z9o1w9k1hDqoBvNNSIWhlBGOa4XTJbEo+ogIMZAskypXsAP7uL9oswqBVhRXUmiAwJKvz8"
            + "7J1PASkokaI3l87vwwValdXPMX7XJZ7zuHL0RjsR27aEomVMJKWAs0ZySQdZO18ghw4N4O1/2Sf1xnCLPbdnrDvzH8OYd2NsZbxqUonU"
            + "tGTMwqXZcX1sNbWB+KQmA4egwRxU1w=="
        ).Decode64();

        public static readonly byte[] RsaP = (
            "22JmIOSSbJ3B4kSOI8U1v/bmL6SQ26mL8qVG5KdnWEvpD8iXmuASC6Ban6T8lXmwbAaRjE8shENQre6Zr2301t/LzZmH10PrcYreX7ig"
            + "fjBD6MUN5qm9eEvE7RavusIyUeZri1cDbbXgzaUJL0HTYAUUzcy5e4K9IJVDdkvjoG0="
        ).Decode64();

        public static readonly byte[] RsaQ = (
            "09jTR1viCvjgSdfsh+EHVq4yPcGPGGn7ZyqUZYIwtpHmlH8BINs2l18TKH3j60FUiZVPG91cYYBLAUou+IY9o5x4vSMCCYpR+YNUcSCe"
            + "OhUuHEdDBijcnUiW79/8eukRBzrWNblp15iT/mQJaDsEn61bzylmomQrVftJtLs4p9M="
        ).Decode64();

        public static readonly RSAParameters PrivateKey = new RSAParameters
        {
            D = RsaD,
            DP = RsaDP,
            DQ = RsaDQ,
            Exponent = RsaExponent,
            InverseQ = RsaInverseQ,
            Modulus = RsaModulus,
            P = RsaP,
            Q = RsaQ,
        };

        public class Account
        {
            public Account(string id, string name, string username, string password, string url, string group)
            {
                Id = id;
                Name = name;
                Username = username;
                Password = password;
                Url = url;
                Group = group;
            }

            public string Id { get; private set; }
            public string Name { get; private set; }
            public string Username { get; private set; }
            public string Password { get; private set; }
            public string Url { get; private set; }
            public string Group { get; private set; }
        }

        // TOOD: Move to a fixture?
        public static readonly Account[] Accounts = new[]
        {
            new Account(
                "1872745596",
                "Muller, Morar and Wisoky",
                "branson_cormier",
                "8jgLCzQSkB2rTZ1OtF9sNGpc",
                "http://nienow.net/meagan.greenholt",
                "three"
            ),
            new Account(
                "1872745606",
                "goyette.net",
                "kris_quigley@baileyjewe.biz",
                "S5@3^wPv!6JsFj",
                "http://bechtelar.biz/tristian.barrows",
                "four"
            ),
            new Account("1872745616", "Ward Inc", "angela_emard", "zp8N@KoWyS0IYu7VR$dvBF!t", "http://schuster.name/ashton", "one"),
            new Account("1872745626", "stehr.com", "bailee_marvin@mohrlegros.net", "cupiditate", "http://runolfon.org/te", "three"),
            new Account("1872745636", "kiehn.biz", "freda", "et", "http://hintzprohaska.biz/wade.fisher", "one"),
            new Account("1872745646", "Jacobs and Sons", "johnnie.hand", "gzyl6714", "http://schultzheaney.org/arvid", "(none)"),
            new Account("1872745656", "Larkin, Kautzer and Wiegand", "hilton", "zguovmdr8703", "http://streich.com/ramona", "one"),
            new Account("1872745666", "Conn Inc", "malvina_paucek@nikolausveum.net", "numquam", "http://conn.net/leda", "four"),
            new Account("1872745676", "Block, Sanford and Connelly", "marilie_wolff", "zKcy?U*aCGS^gf@Z", "http://conroy.biz/zachery", "two"),
            new Account("1872745686", "gradyrenner.org", "oswald@ryan.info", "ojgwad28", "http://kihn.org/candice", "(none)"),
            new Account("1872745696", "lesch.net", "nicholas", "Pkc72Lmr1qwI%sNV^d4@GtX", "http://glover.name/jerad", "two"),
            new Account("1872745706", "sipes.biz", "kaitlyn.bernier@reichel.net", "in", "http://mayert.name/jeromy", "two"),
            new Account("1872745716", "Hintz-Herman", "prince.moriette", "0hebvIS@s^BwMc", "http://sanfordwunsch.org/alek", "(none)"),
            new Account("1872745726", "Hammes-Kassulke", "brooke@gloverhintz.net", "paokcs08", "http://lehner.biz/stanley.dooley", "four"),
            new Account("1872745736", "hermann.com", "jasper_dickens", "Ppj2b!rIMLu*@ElTCZU", "http://rolfson.net/jaden", "one"),
            new Account("1872745746", "Veum and Sons", "marquise@quitzonbrown.com", "owsg728", "http://fahey.name/jon_ankunding", "one"),
            new Account(
                "1872745756",
                "Balistreri, Emard and Mayert",
                "verona@willmswhite.info",
                "wnydas6714",
                "http://treutelkiehn.org/marcos",
                "two"
            ),
            new Account("1872745766", "lindkeler.net", "ed", "quia", "http://leffler.info/chaya", "one"),
            new Account("1872745776", "nikolaus.biz", "leonard", "oW9fdvJLkp#%I", "http://brakuswilliamson.com/bret", "(none)"),
            new Account("1872745786", "bartonherzog.net", "dock@vonrueden.net", "beatae", "http://kunzeokuneva.info/shawn_langosh", "three"),
            new Account("1872745796", "howe.org", "chad@walker.biz", "zexfir7951", "http://crooks.com/sandrine", "(none)"),
            new Account("1872745806", "shields.info", "modesto@kunzenicolas.com", "*JDSdp@VyR8f5FOALW", "http://kemmer.org/hilton", "three"),
            new Account(
                "1872745816",
                "kihnabernathy.com",
                "mafalda.treutel@gislason.name",
                "hwuoxizq18",
                "http://trompbernhard.com/trea.hirthe",
                "two"
            ),
            new Account("1872745826", "Gislason and Sons", "torrey@kshlerin.info", "OfZrTFAIq?Uyl9X$", "http://ullrich.info/carlee", "four"),
            new Account("1872745836", "simonis.com", "marco.cronin", "upokmxct57", "http://rippin.name/bonita_hickle", "four"),
            new Account(
                "1872745856",
                "Howell, Beer and Yundt",
                "raegan@cruickshankgreenholt.org",
                "dHPFrtOjieum4L",
                "http://aufderharrunolfsdottir.info/felicia_torphy",
                "two"
            ),
            new Account("1872745866", "Gottlieb-Ernser", "ivory.moore@paucek.com", "fugit", "http://lockmanlynch.net/alba", "four"),
            new Account(
                "1872745876",
                "Emmerich and Sons",
                "lacey.bernier@hansenboyer.com",
                "aqzkolu6021",
                "http://carrollschmitt.com/willy.emard",
                "three"
            ),
            new Account("1872745886", "Gerlach, Kirlin and Roberts", "maiya@bayergusikowski.org", "nhit3214", "http://feil.net/natasha_howe", "one"),
            new Account("1872745896", "ryan.net", "rubie@fahey.org", "aihw^uFgXnC%R", "http://gleasonjakubowski.biz/august", "(none)"),
            new Account(
                "1872745906",
                "Jewess, Wolf and Volkman",
                "kristin_blanda@howekuhlman.biz",
                "nacro5213",
                "http://wilkinsonleannon.name/bud.willms",
                "two"
            ),
            new Account("1872745916", "Ritchie Group", "nathen_ortiz@turner.biz", "XfmN@G%ebsK1Jc$q", "http://price.info/urban", "two"),
            new Account("1872745926", "wiegand.info", "lavon_greenholt", "fzedpuq30", "http://paucekturcotte.org/kadin_gibson", "(none)"),
            new Account("1872745936", "Rohan, Schneider and Daniel", "zella.effertz", "wksei21", "http://runte.com/camryn.hane", "one"),
            new Account("1872745946", "boyle.name", "gennaro_goldner@kovacek.biz", "eaJD#Kb6UAis@M*8jhILk", "http://kulasklein.info/nyasia", "four"),
            new Account("1872745956", "Pouros-Funk", "maudie@fahey.org", "wahkvms6871", "http://schaefer.info/leslie.bogan", "three"),
            new Account("1872745966", "Parisian-Legros", "holly", "et", "http://naderrempel.net/gwen_schmidt", "four"),
            new Account("1872745976", "Rosenbaum-Schulist", "jordy.krajcik", "xqzflsy843", "http://dooley.info/alek_parker", "four"),
            new Account("1872745986", "christiansen.info", "phoebe@larson.info", "bilvs07", "http://johns.name/columbus.dooley", "two"),
            new Account("1872745996", "Hauck, Thiel and VonRueden", "leif", "QVx?JvZ46e1FBmsAi", "http://bauch.org/marlin", "one"),
            new Account("1872746006", "Sipes and Sons", "leland", "ecgs1758", "http://dubuque.com/jacey", "one"),
            new Account("1872746016", "Osinski LLC", "rhoda", "nhwo705", "http://schinner.org/price", "four"),
            new Account("1872746026", "daniel.name", "santina@wiegand.net", "dolorem", "http://torp.net/shyanne.smitham", "(none)"),
            new Account("1872746036", "darekutch.name", "ali", "U*kgl8u1p#QO9xWNnEd0b3", "http://mante.com/caie_streich", "(none)"),
            new Account("1872746046", "grimes.com", "eunice_satterfield@baileymante.net", "ipsam", "http://swaniawski.org/wendell_gaylord", "three"),
            new Account("1872746056", "conn.name", "sandrine", "rv%XVjo#2Id?@4L", "http://rolfson.com/willy_bartell", "(none)"),
            new Account("1872746066", "Kozey-Spinka", "brando.kshlerin", "consequatur", "http://collinsreichel.net/yasmine", "three"),
            new Account("1872746076", "Daugherty LLC", "horacio_schulist@davis.net", "sbxzn64", "http://deckow.net/roosevelt.kshlerin", "four"),
            new Account(
                "1872746086",
                "Lubowitz LLC",
                "maxine@ebertmckenzie.biz",
                "qrcl02",
                "http://considineheidenreich.name/name.christiansen",
                "(none)"
            ),
            new Account("1872746096", "mante.name", "jayne", "xnekizj90", "http://bogisich.net/lori", "four"),
            new Account("1872746106", "Mante LLC", "antonio.turner@sauertorphy.com", "ckomnf175", "http://herzog.name/luigi", "(none)"),
            new Account("1872746116", "Greenholt-Hodkiewicz", "moriah@mccullough.org", "udaxo7451", "http://mann.com/cecile", "three"),
            new Account("1872746126", "Rosenbaum, Sipes and Leffler", "keshaun@schroeder.info", "recusandae", "http://dooley.name/ewald", "two"),
            new Account(
                "1872746136",
                "Fadel, Ferry and Kohler",
                "sister",
                "sUxoLNhl8Kty*Ve76b45G",
                "http://balistrerimcclure.com/jaquan_wilkinson",
                "two"
            ),
            new Account("1872746146", "Schaden-Rosenbaum", "godfrey", "oDVcsx*m!0Rb@NjSyqdGIl", "http://pouros.net/jeremie", "(none)"),
            new Account(
                "1872746156",
                "Monahan, Reinger and McKenzie",
                "christophe.kub@luettgen.name",
                "fLqj&e$TyNo8gd7!",
                "http://keler.info/nikita.lindgren",
                "four"
            ),
            new Account("1872746166", "bednar.info", "roselyn@hickle.com", "*2tiEP&Ic7dT", "http://jaskolski.com/conner_ortiz", "two"),
            new Account("1872746176", "Jewess, Wolf and Feil", "hal", "doloribus", "http://champlin.org/lue_schroeder", "three"),
            new Account("1872746186", "Kunze-Hettinger", "camilla_pagac", "elpbzT08Dvo6NyQF3wPEr", "http://donnellyadams.com/santino", "one"),
            new Account("1872746196", "Jacobs, Toy and Schultz", "billy_boehm@will.biz", "g5X*hRwlmcL6ZM", "http://larkinconsidine.org/leola", "one"),
            new Account("1872746206", "sanford.com", "joy@abbott.org", "rfolun872", "http://runtemoen.name/pierre", "three"),
            new Account("1872746216", "upton.net", "susana.gaylord", "WR4KxbU^@$Vpi%QH9Mv#T", "http://moore.info/pearl", "three"),
            new Account("1872746226", "wiegand.biz", "ashleigh_gutmann", "t7C&j!Ox21oha5sX*f", "http://armstronghackett.name/jaeden", "three"),
            new Account(
                "1872746236",
                "schneider.net",
                "eunice.sauer@ledner.org",
                "U%EFVGnxw2fQ^t*",
                "http://schulistmetz.info/esperanza_cummerata",
                "two"
            ),
            new Account("1872746246", "Swift-Stoltenberg", "katelin_rempel", "labore", "http://beermills.net/danielle", "two"),
            new Account("1872746256", "Heathcote Group", "hope.waters@parisianbruen.info", "EhG7zBTb8OseI", "http://douglas.name/porter", "(none)"),
            new Account("1872746266", "hilpert.com", "phyllis.lemke", "est", "http://donnelly.com/tyrique_langosh", "one"),
            new Account("1872746276", "daviswolff.name", "martine@ryan.com", "incidunt", "http://schoen.info/macy", "one"),
            new Account(
                "1872746286",
                "Bahringer, Prohaska and Mills",
                "merritt_reilly@lynch.info",
                "dyX^xZ3HTKsqFIMeA",
                "http://schuppe.com/rosetta.yundt",
                "(none)"
            ),
            new Account("1872746296", "ledner.name", "billie.lueilwitz@kertzmann.org", "Zi5K6tXh91mJG3EnjBD4r", "http://feil.com/isabelle", "four"),
            new Account("1872746306", "jerdecormier.com", "renee.towne@ruecker.net", "vuzoskg85", "http://mckenzie.net/zaria", "(none)"),
            new Account(
                "1872746316",
                "harbervandervort.org",
                "elta_haag@okuneva.net",
                "2?GVri70HkKceU*m#CZ3x",
                "http://whiteklocko.name/lacey.dare",
                "one"
            ),
            new Account("1872746326", "gulgowskimann.org", "chaz_brakus", "explicabo", "http://okuneva.biz/lisandro", "two"),
            new Account("1872746336", "padbergconn.info", "lenore@ullrich.net", "ORrNKnhuqd7xeULa^YDk", "http://sauerkuvalis.info/braxton", "one"),
            new Account("1872746346", "davis.com", "margarett", "debitis", "http://spinka.info/kendra", "(none)"),
            new Account("1872746366", "Gerlach Inc", "krystel_boyer", "qui", "http://pouromitham.name/efrain", "three"),
            new Account("1872746376", "cummerata.net", "rudy.flatley", "mzqvakic527", "http://heidenreich.net/ryann_hayes", "(none)"),
            new Account("1872746386", "schowalter.name", "hyman.satterfield", "pjts564", "http://okeefedamore.biz/giovani", "one"),
            new Account("1872746396", "McLaughlin-Fadel", "fanny_sporer", "kyti64", "http://dickibosco.biz/zachariah", "four"),
            new Account("1872746406", "Gerlach-Nienow", "treva.block", "csnxhldi893", "http://kunzemurazik.net/johnny.koch", "two"),
            new Account("1872746416", "O'Reilly-Trantow", "grayson", "non", "http://harris.name/rosalind_marquardt", "three"),
            new Account("1872746426", "Larkin-Konopelski", "josianne_walker", "bwms78", "http://runolfsdottir.name/nicklaus_hayes", "two"),
            new Account(
                "1872746436",
                "Swaniawski, Will and Gaylord",
                "jeramie.ohara@nader.org",
                "quia",
                "http://oreilly.info/dahlia_donnelly",
                "(none)"
            ),
            new Account("1872746446", "emmerichgaylord.name", "diana@hansenbeahan.net", "omnis", "http://rath.net/leif_hermann", "three"),
            new Account(
                "1872746456",
                "armstrong.org",
                "genesis@rosenbaumlueilwitz.biz",
                "zHeu%^kxj9Y0Qr4@m*3!ov",
                "http://schmidtmertz.name/kira",
                "one"
            ),
            new Account("1872746466", "Waelchi Group", "trace.heaney@heidenreichbernier.com", "whljnru03", "http://moore.biz/anibal", "two"),
            new Account("1872746476", "fahey.org", "ward_okuneva", "qjnz18", "http://leuschke.com/daphney", "two"),
            new Account("1872746486", "koelpin.info", "dylan.klocko", "vdjlot364", "http://cronin.net/cyril", "three"),
            new Account("1872746496", "Murphy-Breitenberg", "marcia_kreiger", "dacyz723", "http://steuber.com/ali_gibson", "three"),
            new Account("1872746506", "andersondicki.org", "ceasar@lind.com", "nvymdsk14", "http://kertzmann.biz/jaydon_kunze", "four"),
            new Account(
                "1872746516",
                "watersreichel.net",
                "adella_price@beahanblock.biz",
                "maiores",
                "http://gutkowskirau.org/dora.williamson",
                "four"
            ),
            new Account("1872746526", "torphy.biz", "osborne_hackett@davis.org", "wkdcu1265", "http://buckridge.net/lauretta.veum", "four"),
            new Account("1872746536", "Moen-Hermiston", "hildegard@hahn.com", "zbag942", "http://cummingswehner.biz/april", "(none)"),
            new Account("1872746546", "Gaylord-Lowe", "jerrell", "quasi", "http://grady.biz/mohammed_brakus", "(none)"),
            new Account("1872746556", "Bechtelar, Wyman and Thompson", "shanie@batz.biz", "vel", "http://gottlieb.name/elisabeth", "four"),
            new Account("1872746566", "jacobs.info", "lon_champlin@cristlittel.name", "aut", "http://dachgislason.org/alva", "two"),
            new Account(
                "1872746576",
                "ankunding.com",
                "reina_runolfon@altenwerthhilll.net",
                "@g&aWsoTeJEFhHK5wr#4",
                "http://rice.info/giovanny_ebert",
                "two"
            ),
            new Account("1872746586", "Okuneva-Schmitt", "esperanza@kshlerin.com", "djwhba31", "http://glovermckenzie.info/katelynn", "(none)"),
            new Account("1872746596", "jones.name", "elvera", "ewoqt49", "http://sipes.com/joey.metz", "two"),
            new Account("1872746606", "Tromp-Roob", "brisa.mcdermott", "vcnkg254", "http://bernier.org/gage_haag", "three"),
        };
    }
}
