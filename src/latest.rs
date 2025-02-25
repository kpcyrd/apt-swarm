use crate::db::Database;
use crate::errors::*;
use crate::signed::Signed;
use bstr::{BString, ByteSlice};
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::StreamExt;
use sequoia_openpgp::Fingerprint;
use std::str;

pub type Latest = (DateTime<Utc>, Vec<u8>, Vec<u8>, BString, usize);

pub fn parse_date(date: &str) -> Result<DateTime<Utc>> {
    let datetime = NaiveDateTime::parse_from_str(date, "%a, %d %b %Y %T %Z")
        .context("Failed to parse Date header")?;
    Ok(datetime.and_utc())
}

pub fn extract_date_and_attachment(mut data: &[u8]) -> Option<(DateTime<Utc>, &[u8])> {
    let mut date = None;
    let mut attachment = "".as_bytes();
    while !data.is_empty() {
        let (line, trailing) = data.split_once_str(b"\n").unwrap_or((data, b""));
        if line.is_empty() {
            attachment = trailing;
            break;
        }

        if let Some(value) = line.strip_prefix(b"Date: ") {
            if let Ok(value) = str::from_utf8(value) {
                debug!("Parsing date header: {value:?}");
                date = parse_date(value).ok();
            }
        }

        data = trailing;
    }
    Some((date?, attachment))
}

fn update_latest(latest: &mut Option<Latest>, key: Vec<u8>, bytes: Vec<u8>) -> Result<()> {
    let (signed, _trailing) = Signed::from_bytes(&bytes)?;
    let content = signed.content;

    let Some((date, attachment)) = extract_date_and_attachment(&content) else {
        return Ok(());
    };

    let idx = content.len() - attachment.len();
    let new = Some((date, key, bytes, content, idx));

    // if the new current entry is more recent, update
    // if there's no current latest, `new` always wins
    // if there's a tie in the datetime, it uses the key to break the tie
    if new > *latest {
        *latest = new;
    }

    Ok(())
}

pub async fn find(db: &Database, fp: Fingerprint) -> Result<Option<Latest>> {
    let prefix = format!("{fp}/");
    let stream = db.scan_values(prefix.as_bytes());

    let mut latest = None;

    tokio::pin!(stream);
    while let Some(item) = stream.next().await {
        let (key, value) = item.context("Failed to read from database (scan-latest)")?;
        update_latest(&mut latest, key, value)?;
    }

    Ok(latest)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::header::CryptoHash;
    use chrono::TimeZone;

    #[test]
    fn test_parse_date() {
        assert_eq!(
            parse_date("Wed, 21 Aug 2024 15:36:07 UTC").unwrap(),
            Utc.with_ymd_and_hms(2024, 8, 21, 15, 36, 7).unwrap()
        );
        assert_eq!(
            parse_date("Fri, 14 Feb 2025 11:28:01 UTC").unwrap(),
            Utc.with_ymd_and_hms(2025, 2, 14, 11, 28, 1).unwrap()
        );
        assert_eq!(
            parse_date("Sun, 05 Nov 2023 19:19:57 UTC").unwrap(),
            Utc.with_ymd_and_hms(2023, 11, 5, 19, 19, 57).unwrap()
        );
    }

    #[test]
    fn extract_release_date() {
        let data = b"Origin: Valve Software LLC
Label: Steam launcher
Codename: stable
Date: Wed, 01 Mar 2023 19:01:42 UTC
Architectures: i386 amd64
Components: steam
Description: Steam packages for Ubuntu and Debian
MD5Sum:
 2cc0cb39217ac21fb9d9e3078ffe1c95 2846 steam/binary-i386/Packages
 685cf20f3ec2ac8b73c4619ca8a26bfa 1292 steam/binary-i386/Packages.gz
 1bf3fd71424a1112a232f8617452bc38 135 steam/binary-i386/Release
 0cbb5e2098896d0ec9398430eec59081 2222 steam/binary-amd64/Packages
 baaca0b481c88853e597e5eff662b04a 1101 steam/binary-amd64/Packages.gz
 92c8a3be7382bf8dbe080afc094c799a 136 steam/binary-amd64/Release
 ce8c452267b4804c551a866a0e14936d 1058 steam/source/Sources
 7372595c640f014ab5015417b05bf2b7 591 steam/source/Sources.gz
 6809037802698e089478642ab605bf38 137 steam/source/Release
SHA1:
 9e97f7b06aad48a50815c6176e95a749553bdf15 2846 steam/binary-i386/Packages
 f8c1cbabbb4443e98e225d7e4b632e9349fba43a 1292 steam/binary-i386/Packages.gz
 137f598735523f918e676cb500218b70394d7265 135 steam/binary-i386/Release
 fe9d79b187dd510d849bf04070a93e60cff3c450 2222 steam/binary-amd64/Packages
 950c55d9408f711f86e173cde80627e42a28c895 1101 steam/binary-amd64/Packages.gz
 6958f751e15104d4a727f38185ec9faf25d04a75 136 steam/binary-amd64/Release
 5f7555981af1f82623b93e2e62a97c03d0e5b44c 1058 steam/source/Sources
 b887a9ff370656af32631317d2184b39d44e9d37 591 steam/source/Sources.gz
 aa51a6ea3e0664c790e78a62c7d4662725d1c35a 137 steam/source/Release
SHA256:
 8a33a3338e878e0bd993b28d660f4075ecfff9f2b9e8e056810dd50b2371eb43 2846 steam/binary-i386/Packages
 8c3109fee36ffc26ac61941c3f243bfdd4932aa90390b89e6c825d9d706673fc 1292 steam/binary-i386/Packages.gz
 d21b7028166ccdac26f4c8c1084dad81d0d1e45f82652bcf1b28d0277b795da0 135 steam/binary-i386/Release
 6637cebce9fa077b22daac68f35bfa91493802fde021701b38f6f8a6866b547c 2222 steam/binary-amd64/Packages
 4199ba44aeb45ebc0697378fe98738f10ff332cab03337529ddcd29ce4d0ac51 1101 steam/binary-amd64/Packages.gz
 9e766d8dedb507da4c41cca732b3eff724f53630efa9dbc798ef78dfdfbc5b41 136 steam/binary-amd64/Release
 87bc01cbcde97b917be01df34cd05772f638c3d8e93eddeba17eedb2d70a2f95 1058 steam/source/Sources
 841ac95be57e35183644e4efed99dfc0d39b6039f049ebcf9815e4e54e3e4d38 591 steam/source/Sources.gz
 4cc31b1d8142f8e6145c2331b198f92c825cf6677205d97227f90268ee8c50d0 137 steam/source/Release
";
        let (date, attachment) = extract_date_and_attachment(data).unwrap();
        assert_eq!(date, Utc.with_ymd_and_hms(2023, 3, 1, 19, 1, 42).unwrap());
        assert_eq!(attachment, b"");
    }

    #[test]
    fn extract_attachment() {
        let data = b"Date: Sat, 22 Feb 2025 05:33:44 UTC
Commit: 07c76667ce66d38cf08bf1e331256d22d338b2a1

\xc3\x28this is\n\narbitrary\nbinary\xf0\x28\x8c\x28";
        let (date, attachment) = extract_date_and_attachment(data).unwrap();
        assert_eq!(date, Utc.with_ymd_and_hms(2025, 2, 22, 5, 33, 44).unwrap());
        assert_eq!(
            attachment,
            b"\xc3\x28this is\n\narbitrary\nbinary\xf0\x28\x8c\x28"
        );
    }

    #[test]
    fn test_datetime_tie() {
        let data = [
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: testing
Codename: trixie
Date: Fri, 15 Nov 2024 11:28:01 UTC
Valid-Until: Wed, 25 Dec 2024 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 4f1c7cdf829350ecd5f19446f105c224 5155 main/binary-amd64/Packages
 5efe887860f463dee1257876419c5ead 2452 main/binary-amd64/Packages.gz
 8993e226d487ae15a57b295ee7163410 72 main/binary-amd64/Release
 301e1861261a0cac8704012e48bf9ae0 5122 main/binary-arm64/Packages
 5a8be3a82df40c1d67a83b6f74031b24 2432 main/binary-arm64/Packages.gz
 04848f1e95e99ecd5266016b54f6ba3b 72 main/binary-arm64/Release
 ebea07f2c2dee778846066370e6e8c89 5151 main/binary-i386/Packages
 69db395f0f704f7c2002ccf3dd675874 2448 main/binary-i386/Packages.gz
 c87b59e471c0b39de0cfca2638377f8f 71 main/binary-i386/Release
 b3c0d559a60239b9ab703ba905aae6f5 2939 main/source/Sources
 fb531fdc96ffc0afcc24ba04dd27fca4 1258 main/source/Sources.gz
 704ca88fd2254271bed6e9700954c775 73 main/source/Release
SHA1:
 88549bebf05677460cd5f3737bba3308ddc00230 5155 main/binary-amd64/Packages
 c93610bbfa153e7128ab46d46115a9d7d306a0e0 2452 main/binary-amd64/Packages.gz
 4790dd0652995711f37417277d9f240f43264004 72 main/binary-amd64/Release
 9648703f6299f925ccdb2e6db73c0dcaabe5a2a2 5122 main/binary-arm64/Packages
 c5b3aadfaac20a671fac0f6f3020926afe1466a7 2432 main/binary-arm64/Packages.gz
 559a5d2deafc73df93436224cae9eb13ce1476b7 72 main/binary-arm64/Release
 acaaf2190ee353082b472faf65a25b1b90ae594c 5151 main/binary-i386/Packages
 2a749e0d470886f56299662ae4830fc10d69eda2 2448 main/binary-i386/Packages.gz
 2c099ef796776b4f026e324a181929a95cb6fd6f 71 main/binary-i386/Release
 669806decc4fbb53899c8ad78ac46f290543b5fd 2939 main/source/Sources
 dd38d54b49f079e5aa2100ef52a480f9a030be98 1258 main/source/Sources.gz
 2ec604f75d95854298c93160692fa5d810497e8d 73 main/source/Release
SHA256:
 affbb204a6e0e18f8b4730bb2fd43f2fefd5c7c1c80e04db702909b38e68764d 5155 main/binary-amd64/Packages
 823125c3308508e8280f3864acfa32ebde37dcde2b66625900871649d965f043 2452 main/binary-amd64/Packages.gz
 1cd4765e05f5d3491b247aab90ae65b779d3b0a5fa93d1076afd87f41a6aef92 72 main/binary-amd64/Release
 b9a81ec0de4b34c36727ac6403de0c69d078d06de3317ec287a7225e83c203d9 5122 main/binary-arm64/Packages
 bb03be229acab70c79d3ff1a874c5c4eca6f2e76f7dfece63190aad3ec1504a2 2432 main/binary-arm64/Packages.gz
 291d5c3dd3e5a5de74cf8ca0261f9881ca8e0d3ea07bbee096d137eacf861bda 72 main/binary-arm64/Release
 41e7710fcee9b0cee79bed7875e79747c383608d772a3bed5b14edb139baba85 5151 main/binary-i386/Packages
 b9ae9259fda7197e0d97d7eefe6e34482a80502a7f4d0cb9e5963c03b51a3670 2448 main/binary-i386/Packages.gz
 03864d020cf80a7bd64d2f3a9122ad40482d2dfd776264534e172d518fe3136d 71 main/binary-i386/Release
 8975f6acf34d666bca543d417913adb832b8b900fcc7aabe1c7671d65e5a6024 2939 main/source/Sources
 e5e0e6695226a4945e873fab8eb694e9ab8af8d94c6dc6373d40968116fda3f8 1258 main/source/Sources.gz
 fe0a611678e47cab4d8cc639eb7249cdfb506151360eab974388532b469753bd 73 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAABCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmc3MEEACgkQdKlBuiGe
yBBYZgf+Oe+kmqQSD10o1O1bNmlFnFv2e81qyAD9Ka96+wDdVzYsoQbd82EE8r9U
tx566aC7fON1+sknc+z+vHlG0PWGrSxE1nzeSi1NoBWl5FjPAy/mPIlatgAfowjK
G4JhAsJKAyKR7WBRWmjWUrSl+HHBP3aB/jcwvrdN2dV4UBVkWJKYWelRTXWmzXOR
VcjmHsFQDkY42wXz8biVCDd+urVLtGLW04m8us/l1ZVSKKATZecTVWYmhD/u+0oH
tBIlcVdR6VgRIhB4QcMLalZJ60kmy+oFz/UI+rId3bnAN4j3tELqfcBhlaC8aLDi
v34DhYj76SPDEB4BdO8q0byuf0Smlw==
=93Mo
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: testing
Codename: trixie
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 4f1c7cdf829350ecd5f19446f105c224 5155 main/binary-amd64/Packages
 5efe887860f463dee1257876419c5ead 2452 main/binary-amd64/Packages.gz
 8993e226d487ae15a57b295ee7163410 72 main/binary-amd64/Release
 301e1861261a0cac8704012e48bf9ae0 5122 main/binary-arm64/Packages
 5a8be3a82df40c1d67a83b6f74031b24 2432 main/binary-arm64/Packages.gz
 04848f1e95e99ecd5266016b54f6ba3b 72 main/binary-arm64/Release
 ebea07f2c2dee778846066370e6e8c89 5151 main/binary-i386/Packages
 69db395f0f704f7c2002ccf3dd675874 2448 main/binary-i386/Packages.gz
 c87b59e471c0b39de0cfca2638377f8f 71 main/binary-i386/Release
 b3c0d559a60239b9ab703ba905aae6f5 2939 main/source/Sources
 fb531fdc96ffc0afcc24ba04dd27fca4 1258 main/source/Sources.gz
 704ca88fd2254271bed6e9700954c775 73 main/source/Release
SHA1:
 88549bebf05677460cd5f3737bba3308ddc00230 5155 main/binary-amd64/Packages
 c93610bbfa153e7128ab46d46115a9d7d306a0e0 2452 main/binary-amd64/Packages.gz
 4790dd0652995711f37417277d9f240f43264004 72 main/binary-amd64/Release
 9648703f6299f925ccdb2e6db73c0dcaabe5a2a2 5122 main/binary-arm64/Packages
 c5b3aadfaac20a671fac0f6f3020926afe1466a7 2432 main/binary-arm64/Packages.gz
 559a5d2deafc73df93436224cae9eb13ce1476b7 72 main/binary-arm64/Release
 acaaf2190ee353082b472faf65a25b1b90ae594c 5151 main/binary-i386/Packages
 2a749e0d470886f56299662ae4830fc10d69eda2 2448 main/binary-i386/Packages.gz
 2c099ef796776b4f026e324a181929a95cb6fd6f 71 main/binary-i386/Release
 669806decc4fbb53899c8ad78ac46f290543b5fd 2939 main/source/Sources
 dd38d54b49f079e5aa2100ef52a480f9a030be98 1258 main/source/Sources.gz
 2ec604f75d95854298c93160692fa5d810497e8d 73 main/source/Release
SHA256:
 affbb204a6e0e18f8b4730bb2fd43f2fefd5c7c1c80e04db702909b38e68764d 5155 main/binary-amd64/Packages
 823125c3308508e8280f3864acfa32ebde37dcde2b66625900871649d965f043 2452 main/binary-amd64/Packages.gz
 1cd4765e05f5d3491b247aab90ae65b779d3b0a5fa93d1076afd87f41a6aef92 72 main/binary-amd64/Release
 b9a81ec0de4b34c36727ac6403de0c69d078d06de3317ec287a7225e83c203d9 5122 main/binary-arm64/Packages
 bb03be229acab70c79d3ff1a874c5c4eca6f2e76f7dfece63190aad3ec1504a2 2432 main/binary-arm64/Packages.gz
 291d5c3dd3e5a5de74cf8ca0261f9881ca8e0d3ea07bbee096d137eacf861bda 72 main/binary-arm64/Release
 41e7710fcee9b0cee79bed7875e79747c383608d772a3bed5b14edb139baba85 5151 main/binary-i386/Packages
 b9ae9259fda7197e0d97d7eefe6e34482a80502a7f4d0cb9e5963c03b51a3670 2448 main/binary-i386/Packages.gz
 03864d020cf80a7bd64d2f3a9122ad40482d2dfd776264534e172d518fe3136d 71 main/binary-i386/Release
 8975f6acf34d666bca543d417913adb832b8b900fcc7aabe1c7671d65e5a6024 2939 main/source/Sources
 e5e0e6695226a4945e873fab8eb694e9ab8af8d94c6dc6373d40968116fda3f8 1258 main/source/Sources.gz
 fe0a611678e47cab4d8cc639eb7249cdfb506151360eab974388532b469753bd 73 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAEBCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBA7PQgA1CoBKtlyBwbiNxB7OhLEFcuSp3U0ufVXtof2R09TvoUut8E8TRrAl10c
q/6YMRA5Wb/uYfrtf0eWlgpXyH442yVFFY+forYrCfrhY54GXQJA6lguL8ZMqUdS
SlES1JzvX65L73guCtbRXpSlcuLT7iTbvHlIIU5QTOtYKo59KdmcF01KPtrLLen1
fzdTlGxq7wPxQid3KuN3eZfZ20RUtU79amZxq8spdlZxN6eVU4orliMRR7YiLzIP
EDMZ1vmPtHw4Hg24YGPC2OOzn2bUIb8TzQ3grbvc0BuvjokbPvZOG5j2jMEJjb+3
RkvVS4tolFfLOk8EQrCD7CdxxLqvZw==
=Ea8d
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: stable
Codename: bookworm
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 ef9461c1420699ca148523e82f1658ae 5165 main/binary-amd64/Packages
 8472a30220841fd71471e513eea7feb5 2446 main/binary-amd64/Packages.gz
 5a232710573bca3aae4b577c16ece1c1 71 main/binary-amd64/Release
 f4bc0d019adf816ed328ef8fc6d14da8 5132 main/binary-arm64/Packages
 6810832523f5872f3a0e9a6d3271932f 2427 main/binary-arm64/Packages.gz
 132565cf1e259a93a021e651e2ab3cd4 71 main/binary-arm64/Release
 66294d5c2544ddcc9de4a63307844213 5161 main/binary-i386/Packages
 7954605c44cec2c6732b09f4bf5146f5 2445 main/binary-i386/Packages.gz
 5768b889feb010e5d4a62ad2003a6da2 70 main/binary-i386/Release
 82b6a307db03b9cbfb6a267a57e64fb2 2953 main/source/Sources
 b7c2043f6c99a9e94d28401946d2d5aa 1258 main/source/Sources.gz
 94aa68972888c3c4340efb5dd97b195e 72 main/source/Release
SHA1:
 cfa9e4e3aeb947faabb55eeee303ef6b3a8a7d9e 5165 main/binary-amd64/Packages
 7af71b12e4d55a900d027a97a13fd925d17fbc08 2446 main/binary-amd64/Packages.gz
 0f979d666f966c427fab567771f55d6f9b963b79 71 main/binary-amd64/Release
 ec30ea663b574cf2ad6a7051b80733130a95967c 5132 main/binary-arm64/Packages
 22d34250fe983afe37b3e09a39e4ed0cf503ffcd 2427 main/binary-arm64/Packages.gz
 88b92baad3148570453a1ca4df4ac8f6c8b33c94 71 main/binary-arm64/Release
 54f6e88fdab6f14055791f59f72f5707ae31ae2c 5161 main/binary-i386/Packages
 c9f0e20778899974b6267219246efc5113bef700 2445 main/binary-i386/Packages.gz
 c2f88e8b760b1fbd8e4fab14f02d7dd022309208 70 main/binary-i386/Release
 48576f3f83997e38c1310c0a25affab6c9fabaa0 2953 main/source/Sources
 859ac4cb8868b4b55253fd1ac8ceef2c010bc0e0 1258 main/source/Sources.gz
 e495ccf6037e86ba98915df00c0fce0839703634 72 main/source/Release
SHA256:
 beab22bc6765408c14e65a66648d01b7c080f0f624c84a8c96fb0ec2e8ee32ee 5165 main/binary-amd64/Packages
 90300ff39af1c8af397ccfd1a8fecffe26717b338f56b7b275c9207aad07ef10 2446 main/binary-amd64/Packages.gz
 679b22e05826dc8eea366e3d9cc42471a9dbd03f95656d3a9541dfafcd82dc00 71 main/binary-amd64/Release
 050f154f3d910bc349a9ff06b8d9c2f6ecfe89005fab4d576f817f6b841407b8 5132 main/binary-arm64/Packages
 b3c372797cdf5aa2310f1d0459d6fd8f2bf17abfc76bb5cb70891995ee745b8d 2427 main/binary-arm64/Packages.gz
 ffd961c4598ade54f231c2679cd0b7e8c346b66aa94cac0752d10deea94ee1d9 71 main/binary-arm64/Release
 68e493ff92bdc6542ff3f86b8e18126c85131a3936313bc4ec868261e77778ed 5161 main/binary-i386/Packages
 6691349d45f13e637acf77b52e4c6358e214336860ca012c4a1e6382cdf467e9 2445 main/binary-i386/Packages.gz
 e9a73c169e4a69b67bfec28ff6fda7a5c2236310cd9efe1d60eae4fb5305c7fa 70 main/binary-i386/Release
 9a17f06b2326c7c48accc85a76e063ed0986ebff994869d95c746a7159ae3f2a 2953 main/source/Sources
 03850f5c767373134f44c5c38ce4e3978ad8128faa118f024ccb264e3d5bb83c 1258 main/source/Sources.gz
 d8476d69da595bd80bfaef1aca6d58129be6ab51257f8d1873a5b85ff1398f49 72 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAABCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBBPUwf7BpPi7d6Pzs9LsPKTizSmkoBx3Lm/KBQDuDSpFhfJYk5yuViP4W3DKn0D
T/MltNF5GFXdvH4Q65kQoTa+4CGc83iKbcej7jDo5q+cMXfOqg1hYi6opIEj9shG
5mRqHWKkLJ96wnc8Mh+YAvK3vIAX40iwOMOlMfZQADBGK7H6gTx4/R4/pn4CgHdS
StzttG8ektIx5lojv0FUUE94NQyF0uKtTqB0RUooTzlV/qLEczv8W9ra6kk2AJuD
6xYp5LOKccdEMO4u27MykwD4MaPricDoErQe7ssD+RSp2fSa9nSnxIjiik4dr9lr
VdqlFDMGH3w/JSHSz1UrespC1RjtMw==
=TUnR
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: unstable
Codename: sid
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 2dcd5ffd7f2f64b7c38fa925d7e96a1e 6260 main/binary-amd64/Packages
 cc6cfcd9826a8c8e8eb51d65c669b130 2915 main/binary-amd64/Packages.gz
 20449ced16157eb8f05d42a478c33e3b 73 main/binary-amd64/Release
 bc775e621485c01622f2397eeb67b8e4 5018 main/binary-arm64/Packages
 3182269d9dc1cb2ef4e18e56e7ac59fd 2416 main/binary-arm64/Packages.gz
 5ddfcea95c0f3ba08f348fafdc2ebaa9 73 main/binary-arm64/Release
 299be9fd66e74f0fd79f5f4623ec4411 6254 main/binary-i386/Packages
 43804ab9928c2362033ac99f15719714 2913 main/binary-i386/Packages.gz
 6b9b53f0e38c1f9360e2b36e9219bf83 72 main/binary-i386/Release
 bf88ece9d707203d82a2b14d8c93bdfe 2848 main/source/Sources
 19685747ecc5d2c86c548ebc0de6590f 1239 main/source/Sources.gz
 3e925b43fce2d4b8af85c7e785c6e401 74 main/source/Release
SHA1:
 b693045f159751607329ef6cf5a47091e6c9eb78 6260 main/binary-amd64/Packages
 daf58cc1700106f872cfc05ab311976204da2f76 2915 main/binary-amd64/Packages.gz
 c35fad9ab6e3c4100c30ca38fb6a2abba5b59871 73 main/binary-amd64/Release
 58de7862604db3a87830814def98bb88da9eae28 5018 main/binary-arm64/Packages
 4c18f89c5561660162f515a0dff512cfef7e0df3 2416 main/binary-arm64/Packages.gz
 93f23ad9365f6eab9c51ff37056c6c10e993cb41 73 main/binary-arm64/Release
 d34782b6e3aa5cd52b974a1f3975ad2992e27050 6254 main/binary-i386/Packages
 a2712d6d50a38d45144bfb4583057f76aaee346e 2913 main/binary-i386/Packages.gz
 357698f11a8138a7da6a483cca6d3b891f5cf52e 72 main/binary-i386/Release
 ec0d9e1baa8368ea60e458f0d30370a78ceabeb2 2848 main/source/Sources
 f43cb2d855e570991461daec3dffbdd402660597 1239 main/source/Sources.gz
 8a76c8851861683bec52c7179f0af99288640f8d 74 main/source/Release
SHA256:
 63480240eb3597f4954914f83aeb4c306cec74e6d47921e03aefeed52845d7e5 6260 main/binary-amd64/Packages
 7b6bab95507a72a44353f79c04057a586b17348bc6845190b1e9946ad4f2a34d 2915 main/binary-amd64/Packages.gz
 6176a6b8747088b9d83774f369efed8fc4b1f22bafe037c47f500b505aa5fd70 73 main/binary-amd64/Release
 3df4bea29a43aa15075d59d25a8a892702a45bd6e2dcc379f97ed3409b85155c 5018 main/binary-arm64/Packages
 36309b5c3d598a2ac72aff088825d01c194d339041465287ec1eff477e8b274c 2416 main/binary-arm64/Packages.gz
 e0abbf1c817cb66436db607a507c8b579fb059e3e54369ca979d8cbc0177e307 73 main/binary-arm64/Release
 2887da6b3403ce4de428a1ec59aab76c5b15d6074ee7b4b15e40d9dd796b6afe 6254 main/binary-i386/Packages
 1868b7f7c167f38eac694ad2fe62af9e0828f5176d4e50cf4ee0c78ffb8d3505 2913 main/binary-i386/Packages.gz
 241bd9dee8cb13dd5bbc4b41d496d5e096dfd292db7bb0443df532ea2582cf26 72 main/binary-i386/Release
 66b48d52df535c3b3c5841472524aaf3c3589a06195670f2ad309ba80dd1ba94 2848 main/source/Sources
 b3871901256f870704056586c696edbd27af9535b580836b6f3d3130f124a69f 1239 main/source/Sources.gz
 eafd75f908427c7b1b03f83a7fcd4884d4aced30433b64211c71a062d40b324f 74 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAABCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBDoqAf+N/nWI6wvXlqihgoMKGeUhkI+YKhu+1X89r8bLxLazgmQ1sAnj/cjPWCz
x3XBOEOgfiwo7qUgsW9xYv8pg2JBbFugF/zOmI3kZ7MUCEmZC22ebapr0iRdJpBc
xvXInkkBCYxFtFuGR5eDC+6v2idpj8i+S9UPkBh4osK641iEHzdv4w0dJynWVJNd
pLM7TgmdEYzOwoCsSNoPySlOYGbNZQt/90b3bkh0YSeBzTBo5NDexNkl3xgcWkaW
zD8TJGKfNwI7ExNiR9+Cfw/12QnE2jhuadKzDKHS5WI+qJArfFZR+m1H/seJnZnG
b5XduXB/PK6BAcdfR9AFIgRwnvGoWg==
=6F6z
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: unstable
Codename: sid
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 2dcd5ffd7f2f64b7c38fa925d7e96a1e 6260 main/binary-amd64/Packages
 cc6cfcd9826a8c8e8eb51d65c669b130 2915 main/binary-amd64/Packages.gz
 20449ced16157eb8f05d42a478c33e3b 73 main/binary-amd64/Release
 bc775e621485c01622f2397eeb67b8e4 5018 main/binary-arm64/Packages
 3182269d9dc1cb2ef4e18e56e7ac59fd 2416 main/binary-arm64/Packages.gz
 5ddfcea95c0f3ba08f348fafdc2ebaa9 73 main/binary-arm64/Release
 299be9fd66e74f0fd79f5f4623ec4411 6254 main/binary-i386/Packages
 43804ab9928c2362033ac99f15719714 2913 main/binary-i386/Packages.gz
 6b9b53f0e38c1f9360e2b36e9219bf83 72 main/binary-i386/Release
 bf88ece9d707203d82a2b14d8c93bdfe 2848 main/source/Sources
 19685747ecc5d2c86c548ebc0de6590f 1239 main/source/Sources.gz
 3e925b43fce2d4b8af85c7e785c6e401 74 main/source/Release
SHA1:
 b693045f159751607329ef6cf5a47091e6c9eb78 6260 main/binary-amd64/Packages
 daf58cc1700106f872cfc05ab311976204da2f76 2915 main/binary-amd64/Packages.gz
 c35fad9ab6e3c4100c30ca38fb6a2abba5b59871 73 main/binary-amd64/Release
 58de7862604db3a87830814def98bb88da9eae28 5018 main/binary-arm64/Packages
 4c18f89c5561660162f515a0dff512cfef7e0df3 2416 main/binary-arm64/Packages.gz
 93f23ad9365f6eab9c51ff37056c6c10e993cb41 73 main/binary-arm64/Release
 d34782b6e3aa5cd52b974a1f3975ad2992e27050 6254 main/binary-i386/Packages
 a2712d6d50a38d45144bfb4583057f76aaee346e 2913 main/binary-i386/Packages.gz
 357698f11a8138a7da6a483cca6d3b891f5cf52e 72 main/binary-i386/Release
 ec0d9e1baa8368ea60e458f0d30370a78ceabeb2 2848 main/source/Sources
 f43cb2d855e570991461daec3dffbdd402660597 1239 main/source/Sources.gz
 8a76c8851861683bec52c7179f0af99288640f8d 74 main/source/Release
SHA256:
 63480240eb3597f4954914f83aeb4c306cec74e6d47921e03aefeed52845d7e5 6260 main/binary-amd64/Packages
 7b6bab95507a72a44353f79c04057a586b17348bc6845190b1e9946ad4f2a34d 2915 main/binary-amd64/Packages.gz
 6176a6b8747088b9d83774f369efed8fc4b1f22bafe037c47f500b505aa5fd70 73 main/binary-amd64/Release
 3df4bea29a43aa15075d59d25a8a892702a45bd6e2dcc379f97ed3409b85155c 5018 main/binary-arm64/Packages
 36309b5c3d598a2ac72aff088825d01c194d339041465287ec1eff477e8b274c 2416 main/binary-arm64/Packages.gz
 e0abbf1c817cb66436db607a507c8b579fb059e3e54369ca979d8cbc0177e307 73 main/binary-arm64/Release
 2887da6b3403ce4de428a1ec59aab76c5b15d6074ee7b4b15e40d9dd796b6afe 6254 main/binary-i386/Packages
 1868b7f7c167f38eac694ad2fe62af9e0828f5176d4e50cf4ee0c78ffb8d3505 2913 main/binary-i386/Packages.gz
 241bd9dee8cb13dd5bbc4b41d496d5e096dfd292db7bb0443df532ea2582cf26 72 main/binary-i386/Release
 66b48d52df535c3b3c5841472524aaf3c3589a06195670f2ad309ba80dd1ba94 2848 main/source/Sources
 b3871901256f870704056586c696edbd27af9535b580836b6f3d3130f124a69f 1239 main/source/Sources.gz
 eafd75f908427c7b1b03f83a7fcd4884d4aced30433b64211c71a062d40b324f 74 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAEBCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBApxwf9EAE4fnC6Iyhn0n15WQikVPojEcn2MPjS8r4OtBVHRHMal5js6ZDN15JE
GmQZP7vHqC12Yxifmp2mOkoVlwVvGeHPwb0m/h2FSHy5P6CADq/9CPwjVYbVORkQ
oWo4AOJu/jNnRe9wYQFCRO1mxzcms17Rv8d0UBN6bSLvwJH+Qpvr32v4JzaOomZN
HfII2Te8vZzdptZdssBYupKO0hVCJIRYykrQBy3FbIQN6dzP7GD/oygoBsa1t7Cj
JCGaSpnOBrFV5UwPuX+6k5J17cuF9c/d0E5rLzGnLiaYxl9Jk9deu/muvGKME/jk
xmfGz8KEqUZylajBN7f6JfhPFpL1ZA==
=sS4f
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: testing
Codename: trixie
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 4f1c7cdf829350ecd5f19446f105c224 5155 main/binary-amd64/Packages
 5efe887860f463dee1257876419c5ead 2452 main/binary-amd64/Packages.gz
 8993e226d487ae15a57b295ee7163410 72 main/binary-amd64/Release
 301e1861261a0cac8704012e48bf9ae0 5122 main/binary-arm64/Packages
 5a8be3a82df40c1d67a83b6f74031b24 2432 main/binary-arm64/Packages.gz
 04848f1e95e99ecd5266016b54f6ba3b 72 main/binary-arm64/Release
 ebea07f2c2dee778846066370e6e8c89 5151 main/binary-i386/Packages
 69db395f0f704f7c2002ccf3dd675874 2448 main/binary-i386/Packages.gz
 c87b59e471c0b39de0cfca2638377f8f 71 main/binary-i386/Release
 b3c0d559a60239b9ab703ba905aae6f5 2939 main/source/Sources
 fb531fdc96ffc0afcc24ba04dd27fca4 1258 main/source/Sources.gz
 704ca88fd2254271bed6e9700954c775 73 main/source/Release
SHA1:
 88549bebf05677460cd5f3737bba3308ddc00230 5155 main/binary-amd64/Packages
 c93610bbfa153e7128ab46d46115a9d7d306a0e0 2452 main/binary-amd64/Packages.gz
 4790dd0652995711f37417277d9f240f43264004 72 main/binary-amd64/Release
 9648703f6299f925ccdb2e6db73c0dcaabe5a2a2 5122 main/binary-arm64/Packages
 c5b3aadfaac20a671fac0f6f3020926afe1466a7 2432 main/binary-arm64/Packages.gz
 559a5d2deafc73df93436224cae9eb13ce1476b7 72 main/binary-arm64/Release
 acaaf2190ee353082b472faf65a25b1b90ae594c 5151 main/binary-i386/Packages
 2a749e0d470886f56299662ae4830fc10d69eda2 2448 main/binary-i386/Packages.gz
 2c099ef796776b4f026e324a181929a95cb6fd6f 71 main/binary-i386/Release
 669806decc4fbb53899c8ad78ac46f290543b5fd 2939 main/source/Sources
 dd38d54b49f079e5aa2100ef52a480f9a030be98 1258 main/source/Sources.gz
 2ec604f75d95854298c93160692fa5d810497e8d 73 main/source/Release
SHA256:
 affbb204a6e0e18f8b4730bb2fd43f2fefd5c7c1c80e04db702909b38e68764d 5155 main/binary-amd64/Packages
 823125c3308508e8280f3864acfa32ebde37dcde2b66625900871649d965f043 2452 main/binary-amd64/Packages.gz
 1cd4765e05f5d3491b247aab90ae65b779d3b0a5fa93d1076afd87f41a6aef92 72 main/binary-amd64/Release
 b9a81ec0de4b34c36727ac6403de0c69d078d06de3317ec287a7225e83c203d9 5122 main/binary-arm64/Packages
 bb03be229acab70c79d3ff1a874c5c4eca6f2e76f7dfece63190aad3ec1504a2 2432 main/binary-arm64/Packages.gz
 291d5c3dd3e5a5de74cf8ca0261f9881ca8e0d3ea07bbee096d137eacf861bda 72 main/binary-arm64/Release
 41e7710fcee9b0cee79bed7875e79747c383608d772a3bed5b14edb139baba85 5151 main/binary-i386/Packages
 b9ae9259fda7197e0d97d7eefe6e34482a80502a7f4d0cb9e5963c03b51a3670 2448 main/binary-i386/Packages.gz
 03864d020cf80a7bd64d2f3a9122ad40482d2dfd776264534e172d518fe3136d 71 main/binary-i386/Release
 8975f6acf34d666bca543d417913adb832b8b900fcc7aabe1c7671d65e5a6024 2939 main/source/Sources
 e5e0e6695226a4945e873fab8eb694e9ab8af8d94c6dc6373d40968116fda3f8 1258 main/source/Sources.gz
 fe0a611678e47cab4d8cc639eb7249cdfb506151360eab974388532b469753bd 73 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAABCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBCu9gf/diaKUJFDU9Ed/av5Y3ClsGFUtRuHFMeTY4mfqVRSWj7eDhCjJqrfIxpJ
TsVMMYghdrGG2Dl2M3npbT/HC7/1am+Zs914z4vsmnJKYhyIeb0I9WK89zNIg05q
r7rT4MFuHC78HX8+Wvh8Oq8WWFj/eL/YZmVskDO3HISThE21N3DkDzRuu1Fxg4/m
4clPWI4bXo+JD+A/FWvLISzEdlpWlNKq+SuarCKa76EV0Az+RiiLmj0/mEY1p/gI
6VAinjieOVaw/Th5feF+JAhJ7wzKdoscVdv8MZ1yJijRAjBjDu4P2mYw0NCQipXO
GVTwJIeTkG0B0NTYBrIpMgC9MyQQhQ==
=7brN
-----END PGP SIGNATURE-----
"
            .as_bytes(),
            "-----BEGIN PGP SIGNED MESSAGE-----

Origin: TorProject
Suite: stable
Codename: bookworm
Date: Fri, 14 Feb 2025 11:28:01 UTC
Valid-Until: Wed, 26 Mar 2025 11:28:01 UTC
Architectures: amd64 arm64 i386
Components: main
MD5Sum:
 ef9461c1420699ca148523e82f1658ae 5165 main/binary-amd64/Packages
 8472a30220841fd71471e513eea7feb5 2446 main/binary-amd64/Packages.gz
 5a232710573bca3aae4b577c16ece1c1 71 main/binary-amd64/Release
 f4bc0d019adf816ed328ef8fc6d14da8 5132 main/binary-arm64/Packages
 6810832523f5872f3a0e9a6d3271932f 2427 main/binary-arm64/Packages.gz
 132565cf1e259a93a021e651e2ab3cd4 71 main/binary-arm64/Release
 66294d5c2544ddcc9de4a63307844213 5161 main/binary-i386/Packages
 7954605c44cec2c6732b09f4bf5146f5 2445 main/binary-i386/Packages.gz
 5768b889feb010e5d4a62ad2003a6da2 70 main/binary-i386/Release
 82b6a307db03b9cbfb6a267a57e64fb2 2953 main/source/Sources
 b7c2043f6c99a9e94d28401946d2d5aa 1258 main/source/Sources.gz
 94aa68972888c3c4340efb5dd97b195e 72 main/source/Release
SHA1:
 cfa9e4e3aeb947faabb55eeee303ef6b3a8a7d9e 5165 main/binary-amd64/Packages
 7af71b12e4d55a900d027a97a13fd925d17fbc08 2446 main/binary-amd64/Packages.gz
 0f979d666f966c427fab567771f55d6f9b963b79 71 main/binary-amd64/Release
 ec30ea663b574cf2ad6a7051b80733130a95967c 5132 main/binary-arm64/Packages
 22d34250fe983afe37b3e09a39e4ed0cf503ffcd 2427 main/binary-arm64/Packages.gz
 88b92baad3148570453a1ca4df4ac8f6c8b33c94 71 main/binary-arm64/Release
 54f6e88fdab6f14055791f59f72f5707ae31ae2c 5161 main/binary-i386/Packages
 c9f0e20778899974b6267219246efc5113bef700 2445 main/binary-i386/Packages.gz
 c2f88e8b760b1fbd8e4fab14f02d7dd022309208 70 main/binary-i386/Release
 48576f3f83997e38c1310c0a25affab6c9fabaa0 2953 main/source/Sources
 859ac4cb8868b4b55253fd1ac8ceef2c010bc0e0 1258 main/source/Sources.gz
 e495ccf6037e86ba98915df00c0fce0839703634 72 main/source/Release
SHA256:
 beab22bc6765408c14e65a66648d01b7c080f0f624c84a8c96fb0ec2e8ee32ee 5165 main/binary-amd64/Packages
 90300ff39af1c8af397ccfd1a8fecffe26717b338f56b7b275c9207aad07ef10 2446 main/binary-amd64/Packages.gz
 679b22e05826dc8eea366e3d9cc42471a9dbd03f95656d3a9541dfafcd82dc00 71 main/binary-amd64/Release
 050f154f3d910bc349a9ff06b8d9c2f6ecfe89005fab4d576f817f6b841407b8 5132 main/binary-arm64/Packages
 b3c372797cdf5aa2310f1d0459d6fd8f2bf17abfc76bb5cb70891995ee745b8d 2427 main/binary-arm64/Packages.gz
 ffd961c4598ade54f231c2679cd0b7e8c346b66aa94cac0752d10deea94ee1d9 71 main/binary-arm64/Release
 68e493ff92bdc6542ff3f86b8e18126c85131a3936313bc4ec868261e77778ed 5161 main/binary-i386/Packages
 6691349d45f13e637acf77b52e4c6358e214336860ca012c4a1e6382cdf467e9 2445 main/binary-i386/Packages.gz
 e9a73c169e4a69b67bfec28ff6fda7a5c2236310cd9efe1d60eae4fb5305c7fa 70 main/binary-i386/Release
 9a17f06b2326c7c48accc85a76e063ed0986ebff994869d95c746a7159ae3f2a 2953 main/source/Sources
 03850f5c767373134f44c5c38ce4e3978ad8128faa118f024ccb264e3d5bb83c 1258 main/source/Sources.gz
 d8476d69da595bd80bfaef1aca6d58129be6ab51257f8d1873a5b85ff1398f49 72 main/source/Release
-----BEGIN PGP SIGNATURE-----

wsBzBAEBCAAdFiEEImXrTLK/iNkAro0bdKlBuiGeyBAFAmevKMEACgkQdKlBuiGe
yBAoDQf/Uii8ah8gAAoVqxe5RvUCUdI7rULIPcxfIt9G6ddJDXzvCkgMbq9VqxoL
v+x6qdKjD9tAy+uoeWQygin/aUSD0uPC2d1XXdVvin9A/mTkUxa9C6f84ecxtaQP
TnSNFaQuE6hUlmekB4AFKhBev0N25cezgJC86Cwxsjqub5h1R4anALvHYLqr8p1P
k1LMCwN6nQVIy8dMz6RbN9o69qDIs7yUPhVG5RFN4us8g5A3YDOMFbLJUY2WAiCm
t96GZIs+oOO03g7xqtJc9G67fULuo4TycW70P9yFk5A/+a0m0/ovWuvvjode9iDM
hhRmafsYupear5ln4kdTQgJhH7k9zw==
=VXJQ
-----END PGP SIGNATURE-----
"
            .as_bytes(),
        ];

        let mut latest = None;
        for bytes in data {
            let key = CryptoHash::calculate(bytes);
            update_latest(&mut latest, key.0.into_bytes(), bytes.to_vec()).unwrap();
        }
        assert_eq!(
            latest,
            Some((
                Utc.with_ymd_and_hms(2025, 2, 14, 11, 28, 1).unwrap(),
                "sha256:c4dde6759a31026a6a2b8d3a72dbd8290d0b831568d409ccf51660cdb52bf055".into(),
                data[3].to_vec(),
                Signed::from_bytes(data[3]).unwrap().0.content,
                2986,
            ))
        );
    }
}
