use crate::errors::*;
use crate::signed::Signed;
use bstr::ByteSlice;
use gix_object::{CommitRef, WriteTo};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Kind {
    Commit,
    Tag,
}

pub fn convert(kind: Option<Kind>, buf: &[u8]) -> Result<Signed> {
    let signed = match kind {
        Some(Kind::Commit) => {
            let mut commit = CommitRef::from_bytes(buf).context("Failed to decode as commit")?;

            let mut signature = None;
            for (k, v) in &commit.extra_headers {
                if k.as_bytes() == b"gpgsig" {
                    signature = Some(v.to_vec());
                }
            }

            let signature = signature.context("Provided commit is not signed")?;

            commit
                .extra_headers
                .retain(|(k, _v)| k.as_bytes() != b"gpgsig");

            let mut msg = b"-----BEGIN PGP SIGNED MESSAGE-----\n\n".to_vec();
            commit.write_to(&mut msg)?;
            msg.extend(&signature);
            msg.push(b'\n');

            let (signed, _) = Signed::from_bytes(&msg)?;
            signed
        }
        Some(Kind::Tag) => {
            // TODO: if we instead search for the start of the signature we could do this more efficiently
            let mut msg = b"-----BEGIN PGP SIGNED MESSAGE-----\n\n".to_vec();
            msg.extend(buf);

            let (signed, _) = Signed::from_bytes(&msg)?;
            signed
        }
        None => bail!("git objects with loose header are not supported yet"),
    };

    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plumbing::Keyring;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    const KEYRING: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBE64OEUBEADPS1v+zoCdKA6zyfUtVIaBoIwMhCibqurXi30tVoC9LgM6W1ve
HwPFukWq7DAS0mZUPE3mSV63JFLaTy0bY/6GO1D4wLdWZx4ppH7XKNCvKCbsi70k
UozFykNVf+83WEskuF1oYzXlF3aB5suz2IWJl7ey1EXgIpehwQaTJUA5JIWYFp9A
566LRNJefYMzUR33xc4dRKj6Etg0xdLVq7/vZoo8HpLCBGNWiP0AKqFWEwTg0xQL
7nsJA5tfJJdwAJvrzjpFsvb63PKG6waAtdHhON4q7E2Udak9fz2tRjxA5l9l2zXk
aqsysUzkxPhNjwMENoQ04KZg4aT+ZhhBzTowSWLp3KV2uaZ66kdPUO3s+/1bPp5/
N/IlykaUwyL773iYOZ5dOY/9hIuX/zssihcrGEMW6yIyZR5uKhzYdaM9ExTXP637
UccgNS9/pskPGPx/xK23NDCfeHzL9YHS5KokA2wb/b9hqpwvLaeblbMl2pt79F1R
ac+rZlrRyX3NvlTQP4hqM9Ei2YBAU7QFDJEjH8pVIceL7grxi1Ju1iD5QiSK+je5
Jj5EAikfwSeAttSzsqNvaXJHfABrv5mkkVt1z3icP3HIHTYnG+uj+t8kvW+o9/1i
pD6e6LUh4w5v1aY9kaK/M3+eBH59yNYI99crPUKUBVfW4gv4DBUJAQTWRQARAQAB
tDVMZXZlbnRlIFBvbHlhayAoYW50aHJheHgpIDxsZXZlbnRlQGxldmVudGVwb2x5
YWsubmV0PokCVwQTAQoAQQIbAwIeAQIXgAIZAQULCQgHAwUVCgkICwUWAgMBABYh
BOJAtX4sRjC6do4vJvwbVHyNgXLIBQJhecpaBQkW2aqVAAoJEPwbVHyNgXLIP6wP
/0FliJY5uz5Kmnd7QstUzscF2Ok76bj4bIRDeMTUw1nKPvyEuiXg4P0Kdc+pgIpZ
UXl8J0ASru6c++M6HJSbZA3opCl832ZWgxZR6Od5+kdaRt2YwgFfXStPmktLcNk+
DSIB1JPcFGuok7BNVQuQCgZ9XCW7YEevO6CQFCPPTUgWzDbD/e+Vk8MYN2bERrJ/
GFv2DuF++GILo53aUfhd9Bl2Z6R2mQCSPeeFCd908e+uMV9fAviUY8eDYx1DuJzs
eEdW3P0jdf7bK/384mEUz4vTwqoHxgvrQYDudK8WbISQzWlrJSD3dhQxsRa5cJPB
/RII+m/YPAfARns9/Lk9vvjVzC5giNBUKhYoHurdNHyW6QYcGJkVMAtH6TxJKOKP
RqcM4T4RbYbO1ZUlsB1V2zX/1rWdYRIdMLW0O6wrSZlGFs4PxwXci6KQ0ZjZGLFA
RCPt2OIcFoUMoFA9tL/DycyI1f3cTaw9blvhXtuUnAU5SxyNYBWBjh9kuPCmxlEp
StBIX80jApF6HCp/pxTnsApD3wW+JPsinxuOPMHsgj3hWF5dy5BGSALYGCzPVtWb
ZxZZFKegwtujAk3wOGoOETGe4FTU8hfQnDT2xBXz4sayEoLj+KKjOPU0jLWuUTPs
DeY/igM4Ofx7+SfopTAaRKVm3a/Qk1AxHQW51RtQZ2IjtCRMZXZlbnRlIFBvbHlh
ayA8WjNyMC4weDAwQGdtYWlsLmNvbT6JAlQEEwEKAD4CGwMCHgECF4AFCwkIBwMF
FQoJCAsFFgIDAQAWIQTiQLV+LEYwunaOLyb8G1R8jYFyyAUCYXnKYAUJFtmqlQAK
CRD8G1R8jYFyyICCD/48I9kQTchQ8xBpu6yXfRAM5sDelJ2WuLut+HyWxwhyVETh
Ud/8HKtUasBmiXEPphOMhn2AiQM3UFXqUMFzhfJD2dHMgx3HjCmJfJzViCeJIUL7
0xOJhYCmaQSO4gfzPHuvarn8eq1ixbLCXsID5kHWNQ0gHQMOmYF5KzG//oA5KBe7
+FVM0kijzAyWLiZK1i9gskgd3UsNabIpfT2OgHC55ABDy+g7ueXkQ9t+sbS0Btj1
YucSKywXKivoanAmfI3nZTR1opeAPJMC1ks3JbPR+uScPYYI/+MgN3nFp6YxZBoB
II7X87KhJv3HG3YYyP5zEmy2KJPkN4O2rSUWsivH7RVFMQ1zLzqscTKw9uLlWRUj
RT5umB0L3I7D3By6RnJl8I2XrrhID83C93icaPbAtSz0+njrxzuLHCL98SfaKPCy
3WKkLrDS0+99je3F/x3dZg32cgjZDNMhJYABJc3Nt+3X/RG7xsA9q1skOF2klPcH
d7Fa+Q8f/vtpzOY9kmTFCGw99DKT63L+t64r83SU4KH+31I5fwltWRbszt30XiQp
Wvy2w/qAYfy+XKIgNEqr8dCwp6BL3JTsXpK48hYyilBOfLdXPvqsphfgUGF5BRIz
Qw756s1Sc8uQOo1alo6JcC8iB9quX6UjZSGXf3dgFvu4v3KiEDzWnijySW5At7Qn
TGV2ZW50ZSBQb2x5YWsgPGFudGhyYXh4QGFyY2hsaW51eC5vcmc+iQJUBBMBCgA+
AhsDAh4BAheABQsJCAcDBRUKCQgLBRYCAwEAFiEE4kC1fixGMLp2ji8m/BtUfI2B
csgFAmF5ymAFCRbZqpUACgkQ/BtUfI2BcsiZrw/+KU48++ZguIg7rVYHk1zTnPqy
QG8/cPB87K3kY/Tfr5InPHtDMSeyACLat5xvLMYI3xZ2M9XPZMOUqJI5DPpx6rT0
CYBPDjLnWxcma+t2SwcXTpl3bbxMVH3cNuttAniFXLMpr/E8W9LKWgqLc1kUeHHQ
1ig2+PVjKwzU+kRWH1/w6ztPfbhBnaLhnXavDM5O+Pt0mrFWlYFIbRHpDofR6eew
SU8iA6gZyfvWMVXuQWqn9kESPExQw7rdxwXVcOMMgCPsF7Bk5XL5rA6V6L1++CSP
VYly/48CBXYh5h6w2haQStieq3iTHy/+ikvIgWWkYjmKaYietPWoMSmqwUOm0Ab0
1vsC/PQRWSo8TJzJ99qKl1YUiUuRLsElUN+f29MAR/3zC8us7/tlLhl2kk5qSVhQ
uK0GEA/9ilLecDRuJFQL9GyBYDaGcwaIrWzybGdqFEijpKkQXTI8d0YjMU9olBrf
Rq3Nq6Nv9qw3o0CddOwHxi8Xmd8MQszAuED+RqTZ54KIW+5fa9igW7ag15wRW/s6
r26PHBbOS/wRg18xpmFfktcmNA2RalW6Wh2z2E89f8GW96P4vyZmej8sogv7i5Zp
Hmr19kMjxptxA0SfxXa0uJRq5zPQuFt6691JbeuDW5Wa43UGdBiWcnZ3B04L3bzo
8bh5d51zDLBZuYit30O0KExldmVudGUgUG9seWFrIDxhbnRocmF4eEBoYW1idXJn
LmNjYy5kZT6JAlQEEwEKAD4CGwMCHgECF4AFCwkIBwMFFQoJCAsFFgIDAQAWIQTi
QLV+LEYwunaOLyb8G1R8jYFyyAUCYXnKYAUJFtmqlQAKCRD8G1R8jYFyyHGsD/9o
ryb8idUNAFQGJyCaPV/28GzlBfoEtot55dZ95GhfzBK1WeOrvBDpAH8s2gIFQz77
SSZ9jzg8PtzsPHu3wABpXFlw+BoqUW3OVfPrPQFN/Mm/WRYZSgCN5sMbZCuEosNT
uB9Tw0mllLdID+ozpK+S5EJG9Bjbs1i+x9m5UOTJlBg/j1+a2eI9Jdv8RZYXzkeS
rttZUM6MOEA1zWuyzx4xx2hSOtqdWBXcVJiFUoxtwTfg7P8Z/yYfEGPDUduq9wS7
m9tTRTAl7qTFkEHXvY9wBpbEk7wZqEuQ8Ghfxsnw5ErD2LAUrh+DZON0Ma2V9+3W
Rn7gEo6hcK1zKaac5qlELkRbdG2CGGsddWgYW3g/XY4/N5JTNphT/KG7pEBiqNtJ
8jzeqm3VpPHIYre+ATUlkxwCEPU6mSHZtXbf9PtCy46iBPXX3TiINxXu3XnhcSaA
I0rHEQYIc62Tx4hkBoS22HylIIM0ru3O+U69A+GhwsUATBJaLFV0qkQOUq4WE+JF
yXubIdVaZFmUmCO+ydIsIql2Ay06n1wPf4iUY6cKvbSYQED/OnM2HSNrnEicTvmz
3rk6P/lUNORQ0BgXk8jUi7ZIVr5XjD6UpO3Et0MAYbZcqWvVStPh07/HoflpMiMo
pzyB1burEe4q3YGmyF+Z9ISSiEuU9KiZim7e450rXrQpTGV2ZW50ZSBQb2x5YWsg
PGxldmVudGVAbGV2ZW50ZXBvbHlhay5kZT6JAlQEEwEKAD4CGwMCHgECF4AFCwkI
BwMFFQoJCAsFFgIDAQAWIQTiQLV+LEYwunaOLyb8G1R8jYFyyAUCYXnKYAUJFtmq
lQAKCRD8G1R8jYFyyL9WEACz6/6lQPgPiURC3cd+XzKDRSdzlv3+TJdtqVB5GhcF
YO+oeeHYcl5nmswdv8iFG0lKwZrno8n592fyzO4k1CNNo6UXhlbeFAl+3UcLcpdO
cyPEZUnguzhwKAA5+gwHWJY1HDp6S5uYmN+LSHg5XRbj6F21i6HqT5MMMev+Y0oo
OrKTrEvRTiD4tBdz3CyeArbaa36DBn6oSmss4qY1K1W+VS+mZMxiveXUUj1jgSIg
vTMX/xzXm4r34EJM3k/77y0KS7106OZV/9931i7LEgVBFdLN5CTGkjYpuu4Hswe6
5zIt4CWJ696FARJPa8YKgh23cuuXB1YLSuiFb9C8eounkNPKIbwNA9D/h4Tc42zY
cnA73aPtnjFP0aHpwq/jx/fz2Z5PFulyWeXtcycLoAFnCsxfPH3id3vWPk5+DnNe
N+D/7q6TSN4yRz8MJWFqAPywAdiIgitvRHw6H2+lpOEHadtbpGsC2Myi8q9Oj4lo
Xcw1upYOKe/R3JrvTsh1Q88FaK1Qsh1j6spKpM3mv7gDdExaFQm9niO5Dtcqe4XT
VphNBLNXNNpR5cb6s6PiMAPJsmpWoquA7mf6E+kyffBGDu/o2TzciLhAVgQc/IBb
wFPw2EyJ2QMkROjon7P/zoMVI8Zv0yklpAY9CoRJTdtUk8muE3K/GGPmFgHGIvHl
w7Q6TGV2ZW50ZSBQb2x5YWsgKEphYmJlci9YTVBQIG9ubHkpIDxhbnRocmF4eEBq
YWJiZXIuY2NjLmRlPokCVAQTAQoAPgIbAwIeAQIXgAULCQgHAwUVCgkICwUWAgMB
ABYhBOJAtX4sRjC6do4vJvwbVHyNgXLIBQJhecpgBQkW2aqVAAoJEPwbVHyNgXLI
LbEQAJWK95nknjf69qNFtWz0+wEGIrOSp/PF+wroF9WBQYab5IbgH+9WN/YzMp86
EI85piGOcPGnFcv+fp0ViU7R6jIxAuHa9GBNuRo9HgjlXQkE2l+IZj0LyiqkPPVm
XFUcuU9gxN+J0WCqhiZXt0eBHLGaZj1pcDxlPn5Kc2ymp7IOIDEc3JtqG/27y5Bt
wi8oHILlOTkWeucp5RPU2/Ne4/mvW+Bb2HUCd8LTH4k02mWffJWiPhW2X/zsKWLu
aRN2FKZy+1dHvmg5NIaYQTzoPYna5ozQ2ctf8v+/zqCwXB6/zZhLjV0xUir04PU6
POTi0md5/DawDboa3SwlGToTNgKygzjOvCN+KlCJkSPDifqjjX1Z2sHFjnUaPNs/
UZeNnmexOxdm+lxdc0YG8MbXwICOntHeXWvps/4beEOIK3G//HC1X+G0PSjHK0Ph
KYbMAzZmwDxRHBKC0LV4nGMwLeoS4+2C54FeqkgK8v1dUAimIro16RlDw6bAILIZ
S06zSDe8jl8P8hYWE5FBd2lD3qihZVrDk/eJu2Z8FNjmoTN3s6RExvua1ot1hwL1
hfiqQAd4GWynv82aLikb/ayuxeN92n9vhBf6Q1RLsb1xrX8K2gGVFwuOK/yD3XBt
dNj297eMQW9HA3oxbaEsQ7jA/xq2Xiyn2ZH7IXP29wqkVKWbuQINBE64OEUBEAC3
7qhIoSkvg01ZVlLo80qucyv+aENWS/AIk1E2blba0VgqtBxPLVmlcRD91bfRQqO8
hWn14oKJAocxzoM3M4PNLXLa5b/r2xcmmZ4xkB9tDZc/BJ2T9dNs7ncf0XRVxv7q
fD1+dBHJNpR/iL76LDC3b62U5BSeEoKjBkqAIDISR2XWQeTdMvMjzwI3BJ0l6fC9
gJqPXtHoAqxLqgawmZXdNJyKIqcg5WDWZC4z39CUYBTzvwFloAWS7y5bXi7tHpqv
Dfem090E3V6UVTzNKnl/ePtoCI/tFdbkPfpOV5LJW24ovU5zszJy0TunQQDjVU02
92o83Vyu9Yr9mvGPZSkocYWFj/STThZV5AKfmaA+xGXseHYLuoIldz60wyS8lkru
NVn6js+nCRqSUk2nK3pwueNspwGklSlx/taZagfZKvzOx7RPz+Br3kFyFU/UoaN/
eOIcJLhE6NtCsAoBTzJojWgcrJzspCHA7A7rQTssoHaL83RhMh1bDPP5M9NO0BYC
X4SsvdR+jvwoO1R/smlCpZUWfpBbKEsvPxNCKi86gRxt7FBjOpSdEPX4Ep6cyGbH
RI0YXMzQr5aLxi2v5AR3BFFkNs645347C5Mb2piifDeiyyFyA0b+XRNrJqXYt6Il
YF3TirIclwfqG4URZVrYqyuLnV+cmM1KXAdMwaKNYQARAQABiQI8BBgBCgAmAhsM
FiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmF5ymoFCRbZqqUACgkQ/BtUfI2Bcsiq
/BAAh/Y9lNIUe4FyHJDe89/fdWIEeGs/MXjubMHeTjrdvjwB/efYbAsLQu0CCbNk
lzX2GCnsdoXqgEhNMYAu4LnADMIVEGpsfRNMuOFrPmCYas+/G3zJ8H/D8QTtiXrU
2H5x2pjpN2Z9mw+3D7BNLOoOKyjfpdeETSEz1G5+Zd6WgJ2AIVLo1dzz8tI7EqcO
2VVQ/6tpLmK9LSRHM8M5IczSKPOXfwX3OohrOay2m2J/jw4E9Fi8CEpp8DC9YmW0
Q/uMpF8pdveYZ3F44hBgSLXd5PWWqOsWGn6vxHWQxLfTe+IueBo6l7WTBg450RLH
AH+siyyxCEo8VlHQl0FYU5Ju9Dl2aVm6q13lNeFLAt7afUjNHBW5RiTSR4UZCREL
s40JgaCxq/DLim1U77FmJkmGjx96k5FIxBm8CGgjATGpyuOLKHR3DvMOlYxHUB3f
6RwursqzW0RHZsufAnTZsRLog5obVC1xfA/Tqxb4hwarc3YIkGU4lGD7T63eG5p/
UbYHUnJfUjkVQybBgjq1yHh9I0HFnhHP/Ku6X6VasHmee4PxOZl/D/V92gCE3Jw7
4LVDtylhxmZDlshGY7D2minWr4rMPPHquaVqZHC5XT91gVceQTBAjhcY5xRjkMzI
w7k/48/AmnXVPkfjkr0B9p3n+6tWaZ6IfOC6Wai2BTDxzTY=
=NtF6
-----END PGP PUBLIC KEY BLOCK-----
";

    #[test]
    fn verify_tag() -> Result<()> {
        init();
        let buf = b"object f870ab6864bedcf9e5af137214aa9bc726b8299c
type commit
tag 20230105
tagger Levente Polyak <anthraxx@archlinux.org> 1672932047 +0100

Version 20230105
-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmO26s8ACgkQ/BtUfI2B
csifzA//czbzHwvxg+HVJwzUmId4rVt452si+7ucOjG0+dRtcE31zL39FgA3jeqK
zL0z+G/lI7LoINM5FKrakBwXBcBx5TYDvt41P900NTwH0EqR7ZKePdL/gya8B0HN
6RC7SrdVnY/nkibDOHSGOyMBcf5x815oxgHffo+87Fgoz3pTpZmifEMnFs4Kr7oc
C9GMvsBEs8tPztYaBxgXsJ4Sd7ThqqxOa3u82ioiD1K5Wp/RaAaWW3CRpg0RKgg4
pw8HVdNJk1rd42x5K1stSvmdiC6nyZBumaNP3HXMYdkecKRY+Iv5powcQr4kpp61
lwcfTYcwEg5qeWscUlyrOtx0pYh1WHu4rg3HdOy0bwhEwOOIizLzmVArSH43OQRA
DwK9gEvsmZspB1j6xQA/gQqeP7ps4VDJ2hW+NVn4AAMDpLvybSBzHCA6/8fO3Z+m
vSfPc7oxQ4MFlligyrhXFZAa4rhBb3kUDY15P5TcrX6zTUbQA9BDQrQbuRrj+uEP
yLFl/ptRrn+mW+AB80IOD4stu3tTZqKkyV4BMJLou8z2buWN3VN14CbUTGCTUNMW
gEZz7HSkX3WmEJKFBRG45hyDfIx9XqaEbJH0SXcmDzZ1uZ55aD40vBQQcHqZoKLj
7f06imt697ReuFR5bMYjkNMlWmMAYR4ERrEIWBQXnCcY3MpiMx0=
=Sg65
-----END PGP SIGNATURE-----
";
        let keyring = Keyring::new(KEYRING)?;

        let signed = convert(Some(Kind::Tag), buf)?;
        assert_eq!(
            signed,
            Signed {
                content: "object f870ab6864bedcf9e5af137214aa9bc726b8299c
type commit
tag 20230105
tagger Levente Polyak <anthraxx@archlinux.org> 1672932047 +0100

Version 20230105
"
                .into(),
                signature: vec![
                    137, 2, 51, 4, 0, 1, 10, 0, 29, 22, 33, 4, 226, 64, 181, 126, 44, 70, 48, 186,
                    118, 142, 47, 38, 252, 27, 84, 124, 141, 129, 114, 200, 5, 2, 99, 182, 234,
                    207, 0, 10, 9, 16, 252, 27, 84, 124, 141, 129, 114, 200, 159, 204, 15, 255,
                    115, 54, 243, 31, 11, 241, 131, 225, 213, 39, 12, 212, 152, 135, 120, 173, 91,
                    120, 231, 107, 34, 251, 187, 156, 58, 49, 180, 249, 212, 109, 112, 77, 245,
                    204, 189, 253, 22, 0, 55, 141, 234, 138, 204, 189, 51, 248, 111, 229, 35, 178,
                    232, 32, 211, 57, 20, 170, 218, 144, 28, 23, 5, 192, 113, 229, 54, 3, 190, 222,
                    53, 63, 221, 52, 53, 60, 7, 208, 74, 145, 237, 146, 158, 61, 210, 255, 131, 38,
                    188, 7, 65, 205, 233, 16, 187, 74, 183, 85, 157, 143, 231, 146, 38, 195, 56,
                    116, 134, 59, 35, 1, 113, 254, 113, 243, 94, 104, 198, 1, 223, 126, 143, 188,
                    236, 88, 40, 207, 122, 83, 165, 153, 162, 124, 67, 39, 22, 206, 10, 175, 186,
                    28, 11, 209, 140, 190, 192, 68, 179, 203, 79, 206, 214, 26, 7, 24, 23, 176,
                    158, 18, 119, 180, 225, 170, 172, 78, 107, 123, 188, 218, 42, 34, 15, 82, 185,
                    90, 159, 209, 104, 6, 150, 91, 112, 145, 166, 13, 17, 42, 8, 56, 167, 15, 7,
                    85, 211, 73, 147, 90, 221, 227, 108, 121, 43, 91, 45, 74, 249, 157, 136, 46,
                    167, 201, 144, 110, 153, 163, 79, 220, 117, 204, 97, 217, 30, 112, 164, 88,
                    248, 139, 249, 166, 140, 28, 66, 190, 36, 166, 158, 181, 151, 7, 31, 77, 135,
                    48, 18, 14, 106, 121, 107, 28, 82, 92, 171, 58, 220, 116, 165, 136, 117, 88,
                    123, 184, 174, 13, 199, 116, 236, 180, 111, 8, 68, 192, 227, 136, 139, 50, 243,
                    153, 80, 43, 72, 126, 55, 57, 4, 64, 15, 2, 189, 128, 75, 236, 153, 155, 41, 7,
                    88, 250, 197, 0, 63, 129, 10, 158, 63, 186, 108, 225, 80, 201, 218, 21, 190,
                    53, 89, 248, 0, 3, 3, 164, 187, 242, 109, 32, 115, 28, 32, 58, 255, 199, 206,
                    221, 159, 166, 189, 39, 207, 115, 186, 49, 67, 131, 5, 150, 88, 160, 202, 184,
                    87, 21, 144, 26, 226, 184, 65, 111, 121, 20, 13, 141, 121, 63, 148, 220, 173,
                    126, 179, 77, 70, 208, 3, 208, 67, 66, 180, 27, 185, 26, 227, 250, 225, 15,
                    200, 177, 101, 254, 155, 81, 174, 127, 166, 91, 224, 1, 243, 66, 14, 15, 139,
                    45, 187, 123, 83, 102, 162, 164, 201, 94, 1, 48, 146, 232, 187, 204, 246, 110,
                    229, 141, 221, 83, 117, 224, 38, 212, 76, 96, 147, 80, 211, 22, 128, 70, 115,
                    236, 116, 164, 95, 117, 166, 16, 146, 133, 5, 17, 184, 230, 28, 131, 124, 140,
                    125, 94, 166, 132, 108, 145, 244, 73, 119, 38, 15, 54, 117, 185, 158, 121, 104,
                    62, 52, 188, 20, 16, 112, 122, 153, 160, 162, 227, 237, 253, 58, 138, 107, 122,
                    247, 180, 94, 184, 84, 121, 108, 198, 35, 144, 211, 37, 90, 99, 0, 97, 30, 4,
                    70, 177, 8, 88, 20, 23, 156, 39, 24, 220, 202, 98, 51, 29
                ]
            }
        );
        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(
            canonical,
            vec![(
                Some("E240B57E2C4630BA768E2F26FC1B547C8D8172C8".parse()?),
                Signed {
                    content: "object f870ab6864bedcf9e5af137214aa9bc726b8299c
type commit
tag 20230105
tagger Levente Polyak <anthraxx@archlinux.org> 1672932047 +0100

Version 20230105
"
                    .into(),
                    signature: vec![
                        194, 193, 115, 4, 0, 1, 10, 0, 29, 22, 33, 4, 226, 64, 181, 126, 44, 70,
                        48, 186, 118, 142, 47, 38, 252, 27, 84, 124, 141, 129, 114, 200, 5, 2, 99,
                        182, 234, 207, 0, 10, 9, 16, 252, 27, 84, 124, 141, 129, 114, 200, 159,
                        204, 15, 255, 115, 54, 243, 31, 11, 241, 131, 225, 213, 39, 12, 212, 152,
                        135, 120, 173, 91, 120, 231, 107, 34, 251, 187, 156, 58, 49, 180, 249, 212,
                        109, 112, 77, 245, 204, 189, 253, 22, 0, 55, 141, 234, 138, 204, 189, 51,
                        248, 111, 229, 35, 178, 232, 32, 211, 57, 20, 170, 218, 144, 28, 23, 5,
                        192, 113, 229, 54, 3, 190, 222, 53, 63, 221, 52, 53, 60, 7, 208, 74, 145,
                        237, 146, 158, 61, 210, 255, 131, 38, 188, 7, 65, 205, 233, 16, 187, 74,
                        183, 85, 157, 143, 231, 146, 38, 195, 56, 116, 134, 59, 35, 1, 113, 254,
                        113, 243, 94, 104, 198, 1, 223, 126, 143, 188, 236, 88, 40, 207, 122, 83,
                        165, 153, 162, 124, 67, 39, 22, 206, 10, 175, 186, 28, 11, 209, 140, 190,
                        192, 68, 179, 203, 79, 206, 214, 26, 7, 24, 23, 176, 158, 18, 119, 180,
                        225, 170, 172, 78, 107, 123, 188, 218, 42, 34, 15, 82, 185, 90, 159, 209,
                        104, 6, 150, 91, 112, 145, 166, 13, 17, 42, 8, 56, 167, 15, 7, 85, 211, 73,
                        147, 90, 221, 227, 108, 121, 43, 91, 45, 74, 249, 157, 136, 46, 167, 201,
                        144, 110, 153, 163, 79, 220, 117, 204, 97, 217, 30, 112, 164, 88, 248, 139,
                        249, 166, 140, 28, 66, 190, 36, 166, 158, 181, 151, 7, 31, 77, 135, 48, 18,
                        14, 106, 121, 107, 28, 82, 92, 171, 58, 220, 116, 165, 136, 117, 88, 123,
                        184, 174, 13, 199, 116, 236, 180, 111, 8, 68, 192, 227, 136, 139, 50, 243,
                        153, 80, 43, 72, 126, 55, 57, 4, 64, 15, 2, 189, 128, 75, 236, 153, 155,
                        41, 7, 88, 250, 197, 0, 63, 129, 10, 158, 63, 186, 108, 225, 80, 201, 218,
                        21, 190, 53, 89, 248, 0, 3, 3, 164, 187, 242, 109, 32, 115, 28, 32, 58,
                        255, 199, 206, 221, 159, 166, 189, 39, 207, 115, 186, 49, 67, 131, 5, 150,
                        88, 160, 202, 184, 87, 21, 144, 26, 226, 184, 65, 111, 121, 20, 13, 141,
                        121, 63, 148, 220, 173, 126, 179, 77, 70, 208, 3, 208, 67, 66, 180, 27,
                        185, 26, 227, 250, 225, 15, 200, 177, 101, 254, 155, 81, 174, 127, 166, 91,
                        224, 1, 243, 66, 14, 15, 139, 45, 187, 123, 83, 102, 162, 164, 201, 94, 1,
                        48, 146, 232, 187, 204, 246, 110, 229, 141, 221, 83, 117, 224, 38, 212, 76,
                        96, 147, 80, 211, 22, 128, 70, 115, 236, 116, 164, 95, 117, 166, 16, 146,
                        133, 5, 17, 184, 230, 28, 131, 124, 140, 125, 94, 166, 132, 108, 145, 244,
                        73, 119, 38, 15, 54, 117, 185, 158, 121, 104, 62, 52, 188, 20, 16, 112,
                        122, 153, 160, 162, 227, 237, 253, 58, 138, 107, 122, 247, 180, 94, 184,
                        84, 121, 108, 198, 35, 144, 211, 37, 90, 99, 0, 97, 30, 4, 70, 177, 8, 88,
                        20, 23, 156, 39, 24, 220, 202, 98, 51, 29
                    ]
                }
            )]
        );

        Ok(())
    }

    #[test]
    fn verify_commit() -> Result<()> {
        init();
        let buf = b"tree 1b99d17009234a86e65e830c7a7ae6f7d182b8ef
parent d45e77738bda2d17b10f87d05167a12fa5be8d63
author Levente Polyak <anthraxx@archlinux.org> 1673558348 +0100
committer Levente Polyak <anthraxx@archlinux.org> 1673912904 +0100
gpgsig -----BEGIN PGP SIGNATURE-----
 
 iQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmPF4koACgkQ/BtUfI2B
 csjt2g//f4DDzb+z8MoMP9UfLCXy3nTstCxdlIiQQtPz7t9WPhxNxjKZai32UQzW
 4SBlwzErlugnOe0wkZb2olD7X/+/ffKO/s/b32rqxumjzrzpqSXHrrqo9XoL3Aut
 dXrgQ0X+hDRGcwbJS6iT05zJuYV9XXxgY+IKrJPQKveiTNYXS9M04b/kxHPvM4Vl
 gdCAxXKsjSdBxFepepI1vHEZOziEtT/3cB+7Rm2l93AyRuSPG01DZ48xKbIvpsEs
 Pt2X16cQTe0d0OORBVnnRXjhx9CI1QE5+H4ZUm94CW64GOoOtYQV74mtzJMZjuvN
 exdaWciOG/5Jq1QrIWvT4uRCl1mc3+rtjj/S9SPelZb24HqakoCCQE6xf1UAu5F8
 cN+8AyeENizh5xanueiAVwnRKzc07+VzKbKjR5nA4UWaTs6tNMLII6+LPnLnn2Du
 ZUCWEg972TevQ5u9AlkJkUI6JqkucBYc0IQZ8r6A7gg4YrLhbElpC5MY3F/EozGY
 T1jbwndZ/BQFSauImU75eU/JqRTnVi2K+gTXo78U7QaJZuUhhnPxjlbwm4Pgva7X
 cO5e9ZEVYT8PxgT2CrbBmNFDAu3SH87ONiuJR3OibNsjCikTpUIdgcNK8E4A15JR
 M3Qw+dOJUEDzhvDkzFYQ87Liz8ITX7cFgpx9OnkBgVjWi6zl+uo=
 =YZzN
 -----END PGP SIGNATURE-----

commitpkg: abort execution if msg file editor exits none-successfully

Previously the script execution did not abort if the msg file editor
exited none-successfully leading to undesired commits with a potentially
unfinished message. Instead abort the commit if the msg file editor is
deliberately terminated with a failure code.

Signed-off-by: Levente Polyak <anthraxx@archlinux.org>
";

        let keyring = Keyring::new(KEYRING)?;

        let signed = convert(Some(Kind::Commit), buf)?;
        assert_eq!(
            signed,
            Signed {
                content: "tree 1b99d17009234a86e65e830c7a7ae6f7d182b8ef
parent d45e77738bda2d17b10f87d05167a12fa5be8d63
author Levente Polyak <anthraxx@archlinux.org> 1673558348 +0100
committer Levente Polyak <anthraxx@archlinux.org> 1673912904 +0100

commitpkg: abort execution if msg file editor exits none-successfully

Previously the script execution did not abort if the msg file editor
exited none-successfully leading to undesired commits with a potentially
unfinished message. Instead abort the commit if the msg file editor is
deliberately terminated with a failure code.

Signed-off-by: Levente Polyak <anthraxx@archlinux.org>
"
                .into(),
                signature: vec![
                    137, 2, 51, 4, 0, 1, 10, 0, 29, 22, 33, 4, 226, 64, 181, 126, 44, 70, 48, 186,
                    118, 142, 47, 38, 252, 27, 84, 124, 141, 129, 114, 200, 5, 2, 99, 197, 226, 74,
                    0, 10, 9, 16, 252, 27, 84, 124, 141, 129, 114, 200, 237, 218, 15, 255, 127,
                    128, 195, 205, 191, 179, 240, 202, 12, 63, 213, 31, 44, 37, 242, 222, 116, 236,
                    180, 44, 93, 148, 136, 144, 66, 211, 243, 238, 223, 86, 62, 28, 77, 198, 50,
                    153, 106, 45, 246, 81, 12, 214, 225, 32, 101, 195, 49, 43, 150, 232, 39, 57,
                    237, 48, 145, 150, 246, 162, 80, 251, 95, 255, 191, 125, 242, 142, 254, 207,
                    219, 223, 106, 234, 198, 233, 163, 206, 188, 233, 169, 37, 199, 174, 186, 168,
                    245, 122, 11, 220, 11, 173, 117, 122, 224, 67, 69, 254, 132, 52, 70, 115, 6,
                    201, 75, 168, 147, 211, 156, 201, 185, 133, 125, 93, 124, 96, 99, 226, 10, 172,
                    147, 208, 42, 247, 162, 76, 214, 23, 75, 211, 52, 225, 191, 228, 196, 115, 239,
                    51, 133, 101, 129, 208, 128, 197, 114, 172, 141, 39, 65, 196, 87, 169, 122,
                    146, 53, 188, 113, 25, 59, 56, 132, 181, 63, 247, 112, 31, 187, 70, 109, 165,
                    247, 112, 50, 70, 228, 143, 27, 77, 67, 103, 143, 49, 41, 178, 47, 166, 193,
                    44, 62, 221, 151, 215, 167, 16, 77, 237, 29, 208, 227, 145, 5, 89, 231, 69,
                    120, 225, 199, 208, 136, 213, 1, 57, 248, 126, 25, 82, 111, 120, 9, 110, 184,
                    24, 234, 14, 181, 132, 21, 239, 137, 173, 204, 147, 25, 142, 235, 205, 123, 23,
                    90, 89, 200, 142, 27, 254, 73, 171, 84, 43, 33, 107, 211, 226, 228, 66, 151,
                    89, 156, 223, 234, 237, 142, 63, 210, 245, 35, 222, 149, 150, 246, 224, 122,
                    154, 146, 128, 130, 64, 78, 177, 127, 85, 0, 187, 145, 124, 112, 223, 188, 3,
                    39, 132, 54, 44, 225, 231, 22, 167, 185, 232, 128, 87, 9, 209, 43, 55, 52, 239,
                    229, 115, 41, 178, 163, 71, 153, 192, 225, 69, 154, 78, 206, 173, 52, 194, 200,
                    35, 175, 139, 62, 114, 231, 159, 96, 238, 101, 64, 150, 18, 15, 123, 217, 55,
                    175, 67, 155, 189, 2, 89, 9, 145, 66, 58, 38, 169, 46, 112, 22, 28, 208, 132,
                    25, 242, 190, 128, 238, 8, 56, 98, 178, 225, 108, 73, 105, 11, 147, 24, 220,
                    95, 196, 163, 49, 152, 79, 88, 219, 194, 119, 89, 252, 20, 5, 73, 171, 136,
                    153, 78, 249, 121, 79, 201, 169, 20, 231, 86, 45, 138, 250, 4, 215, 163, 191,
                    20, 237, 6, 137, 102, 229, 33, 134, 115, 241, 142, 86, 240, 155, 131, 224, 189,
                    174, 215, 112, 238, 94, 245, 145, 21, 97, 63, 15, 198, 4, 246, 10, 182, 193,
                    152, 209, 67, 2, 237, 210, 31, 206, 206, 54, 43, 137, 71, 115, 162, 108, 219,
                    35, 10, 41, 19, 165, 66, 29, 129, 195, 74, 240, 78, 0, 215, 146, 81, 51, 116,
                    48, 249, 211, 137, 80, 64, 243, 134, 240, 228, 204, 86, 16, 243, 178, 226, 207,
                    194, 19, 95, 183, 5, 130, 156, 125, 58, 121, 1, 129, 88, 214, 139, 172, 229,
                    250, 234
                ]
            }
        );

        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(
            canonical,
            vec![(
                Some("E240B57E2C4630BA768E2F26FC1B547C8D8172C8".parse()?),
                Signed {
                    content: "tree 1b99d17009234a86e65e830c7a7ae6f7d182b8ef
parent d45e77738bda2d17b10f87d05167a12fa5be8d63
author Levente Polyak <anthraxx@archlinux.org> 1673558348 +0100
committer Levente Polyak <anthraxx@archlinux.org> 1673912904 +0100

commitpkg: abort execution if msg file editor exits none-successfully

Previously the script execution did not abort if the msg file editor
exited none-successfully leading to undesired commits with a potentially
unfinished message. Instead abort the commit if the msg file editor is
deliberately terminated with a failure code.

Signed-off-by: Levente Polyak <anthraxx@archlinux.org>
"
                    .into(),
                    signature: vec![
                        194, 193, 115, 4, 0, 1, 10, 0, 29, 22, 33, 4, 226, 64, 181, 126, 44, 70,
                        48, 186, 118, 142, 47, 38, 252, 27, 84, 124, 141, 129, 114, 200, 5, 2, 99,
                        197, 226, 74, 0, 10, 9, 16, 252, 27, 84, 124, 141, 129, 114, 200, 237, 218,
                        15, 255, 127, 128, 195, 205, 191, 179, 240, 202, 12, 63, 213, 31, 44, 37,
                        242, 222, 116, 236, 180, 44, 93, 148, 136, 144, 66, 211, 243, 238, 223, 86,
                        62, 28, 77, 198, 50, 153, 106, 45, 246, 81, 12, 214, 225, 32, 101, 195, 49,
                        43, 150, 232, 39, 57, 237, 48, 145, 150, 246, 162, 80, 251, 95, 255, 191,
                        125, 242, 142, 254, 207, 219, 223, 106, 234, 198, 233, 163, 206, 188, 233,
                        169, 37, 199, 174, 186, 168, 245, 122, 11, 220, 11, 173, 117, 122, 224, 67,
                        69, 254, 132, 52, 70, 115, 6, 201, 75, 168, 147, 211, 156, 201, 185, 133,
                        125, 93, 124, 96, 99, 226, 10, 172, 147, 208, 42, 247, 162, 76, 214, 23,
                        75, 211, 52, 225, 191, 228, 196, 115, 239, 51, 133, 101, 129, 208, 128,
                        197, 114, 172, 141, 39, 65, 196, 87, 169, 122, 146, 53, 188, 113, 25, 59,
                        56, 132, 181, 63, 247, 112, 31, 187, 70, 109, 165, 247, 112, 50, 70, 228,
                        143, 27, 77, 67, 103, 143, 49, 41, 178, 47, 166, 193, 44, 62, 221, 151,
                        215, 167, 16, 77, 237, 29, 208, 227, 145, 5, 89, 231, 69, 120, 225, 199,
                        208, 136, 213, 1, 57, 248, 126, 25, 82, 111, 120, 9, 110, 184, 24, 234, 14,
                        181, 132, 21, 239, 137, 173, 204, 147, 25, 142, 235, 205, 123, 23, 90, 89,
                        200, 142, 27, 254, 73, 171, 84, 43, 33, 107, 211, 226, 228, 66, 151, 89,
                        156, 223, 234, 237, 142, 63, 210, 245, 35, 222, 149, 150, 246, 224, 122,
                        154, 146, 128, 130, 64, 78, 177, 127, 85, 0, 187, 145, 124, 112, 223, 188,
                        3, 39, 132, 54, 44, 225, 231, 22, 167, 185, 232, 128, 87, 9, 209, 43, 55,
                        52, 239, 229, 115, 41, 178, 163, 71, 153, 192, 225, 69, 154, 78, 206, 173,
                        52, 194, 200, 35, 175, 139, 62, 114, 231, 159, 96, 238, 101, 64, 150, 18,
                        15, 123, 217, 55, 175, 67, 155, 189, 2, 89, 9, 145, 66, 58, 38, 169, 46,
                        112, 22, 28, 208, 132, 25, 242, 190, 128, 238, 8, 56, 98, 178, 225, 108,
                        73, 105, 11, 147, 24, 220, 95, 196, 163, 49, 152, 79, 88, 219, 194, 119,
                        89, 252, 20, 5, 73, 171, 136, 153, 78, 249, 121, 79, 201, 169, 20, 231, 86,
                        45, 138, 250, 4, 215, 163, 191, 20, 237, 6, 137, 102, 229, 33, 134, 115,
                        241, 142, 86, 240, 155, 131, 224, 189, 174, 215, 112, 238, 94, 245, 145,
                        21, 97, 63, 15, 198, 4, 246, 10, 182, 193, 152, 209, 67, 2, 237, 210, 31,
                        206, 206, 54, 43, 137, 71, 115, 162, 108, 219, 35, 10, 41, 19, 165, 66, 29,
                        129, 195, 74, 240, 78, 0, 215, 146, 81, 51, 116, 48, 249, 211, 137, 80, 64,
                        243, 134, 240, 228, 204, 86, 16, 243, 178, 226, 207, 194, 19, 95, 183, 5,
                        130, 156, 125, 58, 121, 1, 129, 88, 214, 139, 172, 229, 250, 234
                    ]
                }
            )]
        );

        Ok(())
    }

    #[test]
    fn detect_modified_tag() -> Result<()> {
        init();
        let buf = b"this is
tampered
-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmO26s8ACgkQ/BtUfI2B
csifzA//czbzHwvxg+HVJwzUmId4rVt452si+7ucOjG0+dRtcE31zL39FgA3jeqK
zL0z+G/lI7LoINM5FKrakBwXBcBx5TYDvt41P900NTwH0EqR7ZKePdL/gya8B0HN
6RC7SrdVnY/nkibDOHSGOyMBcf5x815oxgHffo+87Fgoz3pTpZmifEMnFs4Kr7oc
C9GMvsBEs8tPztYaBxgXsJ4Sd7ThqqxOa3u82ioiD1K5Wp/RaAaWW3CRpg0RKgg4
pw8HVdNJk1rd42x5K1stSvmdiC6nyZBumaNP3HXMYdkecKRY+Iv5powcQr4kpp61
lwcfTYcwEg5qeWscUlyrOtx0pYh1WHu4rg3HdOy0bwhEwOOIizLzmVArSH43OQRA
DwK9gEvsmZspB1j6xQA/gQqeP7ps4VDJ2hW+NVn4AAMDpLvybSBzHCA6/8fO3Z+m
vSfPc7oxQ4MFlligyrhXFZAa4rhBb3kUDY15P5TcrX6zTUbQA9BDQrQbuRrj+uEP
yLFl/ptRrn+mW+AB80IOD4stu3tTZqKkyV4BMJLou8z2buWN3VN14CbUTGCTUNMW
gEZz7HSkX3WmEJKFBRG45hyDfIx9XqaEbJH0SXcmDzZ1uZ55aD40vBQQcHqZoKLj
7f06imt697ReuFR5bMYjkNMlWmMAYR4ERrEIWBQXnCcY3MpiMx0=
=Sg65
-----END PGP SIGNATURE-----
";
        let keyring = Keyring::new(KEYRING)?;

        let signed = convert(Some(Kind::Tag), buf)?;
        let canonical = signed.canonicalize(None)?;
        assert_eq!(canonical.len(), 1);

        let signed = convert(Some(Kind::Tag), buf)?;
        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(canonical.len(), 0);

        Ok(())
    }

    #[test]
    fn detect_modified_commit() -> Result<()> {
        init();
        let buf = b"tree ffffffffffffffffffffffffffffffffffffffff
parent eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
author Levente Polyak <anthraxx@archlinux.org> 1673558348 +0100
committer Levente Polyak <anthraxx@archlinux.org> 1673912904 +0100
gpgsig -----BEGIN PGP SIGNATURE-----
 
 iQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmPF4koACgkQ/BtUfI2B
 csjt2g//f4DDzb+z8MoMP9UfLCXy3nTstCxdlIiQQtPz7t9WPhxNxjKZai32UQzW
 4SBlwzErlugnOe0wkZb2olD7X/+/ffKO/s/b32rqxumjzrzpqSXHrrqo9XoL3Aut
 dXrgQ0X+hDRGcwbJS6iT05zJuYV9XXxgY+IKrJPQKveiTNYXS9M04b/kxHPvM4Vl
 gdCAxXKsjSdBxFepepI1vHEZOziEtT/3cB+7Rm2l93AyRuSPG01DZ48xKbIvpsEs
 Pt2X16cQTe0d0OORBVnnRXjhx9CI1QE5+H4ZUm94CW64GOoOtYQV74mtzJMZjuvN
 exdaWciOG/5Jq1QrIWvT4uRCl1mc3+rtjj/S9SPelZb24HqakoCCQE6xf1UAu5F8
 cN+8AyeENizh5xanueiAVwnRKzc07+VzKbKjR5nA4UWaTs6tNMLII6+LPnLnn2Du
 ZUCWEg972TevQ5u9AlkJkUI6JqkucBYc0IQZ8r6A7gg4YrLhbElpC5MY3F/EozGY
 T1jbwndZ/BQFSauImU75eU/JqRTnVi2K+gTXo78U7QaJZuUhhnPxjlbwm4Pgva7X
 cO5e9ZEVYT8PxgT2CrbBmNFDAu3SH87ONiuJR3OibNsjCikTpUIdgcNK8E4A15JR
 M3Qw+dOJUEDzhvDkzFYQ87Liz8ITX7cFgpx9OnkBgVjWi6zl+uo=
 =YZzN
 -----END PGP SIGNATURE-----

this is tampered
";
        let keyring = Keyring::new(KEYRING)?;

        let signed = convert(Some(Kind::Commit), buf)?;
        let canonical = signed.canonicalize(None)?;
        assert_eq!(canonical.len(), 1);

        let signed = convert(Some(Kind::Commit), buf)?;
        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(canonical.len(), 0);

        Ok(())
    }
}
