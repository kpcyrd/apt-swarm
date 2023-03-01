#![no_main]

use apt_swarm::keyring::Keyring;
use apt_swarm::signed::Signed;
use libfuzzer_sys::fuzz_target;

lazy_static::lazy_static! {
    static ref KEYRING: Keyring = Keyring::new(include_bytes!("../../contrib/signal-desktop-keyring.gpg")).unwrap();
}

fuzz_target!(|data: &[u8]| {
    let content = b"Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 23 Feb 2023 21:08:36 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 65649688ba41012818bba9dc6d28b94e   133710 main/binary-amd64/Packages
 b1c787a9483d527e530b54dcd5f833df    21684 main/binary-amd64/Packages.gz
 1fbf9856d1ba6f8afca4b0a89549aa25    17876 main/binary-amd64/Packages.bz2
 24829129844e777b933760f0d503fa01     4804 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 756bbbf6835b9e4328a888d02d5373faa0d6526e   133710 main/binary-amd64/Packages
 1bc67c4e528f2fc563ee2e0b569ba0c2f73a868a    21684 main/binary-amd64/Packages.gz
 155f4cb2d8902e83148f081d3b7fefef6028253d    17876 main/binary-amd64/Packages.bz2
 1016e4f8feecb325d822bbace0c19f332dec9c72     4804 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 4a0e4036dc7591e02989de49fc72426b95fbbf775997ca108447e9d1c8474984   133710 main/binary-amd64/Packages
 4f489cd935732fd044bb43ff3a0589fa4efd8a89ac27b2c46e74f9a042870395    21684 main/binary-amd64/Packages.gz
 73dc6da971f285839b03ff2b784c22a404c1cf91751f8a1a5252789bfda93e87    17876 main/binary-amd64/Packages.bz2
 6075f85cb21aaa5b4b40f9c55688380997a1e975efa7ecd1a985913299723015     4804 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
";

    let orig_signature = [
        137, 2, 28, 4, 1, 1, 8, 0, 6, 5, 2, 99, 247, 213, 214, 0, 10, 9, 16, 217, 128, 161, 116,
        87, 246, 251, 6, 108, 185, 15, 251, 7, 247, 38, 199, 202, 209, 141, 243, 6, 124, 135, 246,
        30, 155, 2, 150, 253, 36, 139, 22, 220, 141, 111, 42, 67, 189, 238, 28, 89, 157, 38, 65,
        111, 234, 185, 142, 244, 150, 208, 241, 106, 13, 235, 109, 13, 171, 147, 9, 23, 55, 21,
        185, 52, 186, 74, 207, 16, 98, 76, 63, 121, 208, 247, 49, 73, 112, 4, 235, 198, 161, 41,
        117, 11, 124, 93, 8, 103, 35, 27, 64, 23, 205, 235, 57, 119, 199, 193, 45, 230, 123, 17,
        111, 37, 204, 4, 144, 238, 189, 28, 46, 181, 42, 22, 234, 88, 35, 141, 119, 183, 56, 55,
        93, 238, 26, 235, 66, 167, 91, 209, 229, 172, 167, 89, 128, 142, 54, 98, 210, 69, 43, 146,
        143, 88, 200, 44, 128, 132, 25, 114, 104, 180, 138, 22, 156, 106, 9, 44, 112, 167, 124, 96,
        234, 42, 67, 249, 78, 255, 201, 194, 104, 62, 130, 230, 58, 94, 30, 121, 104, 163, 175, 39,
        194, 137, 32, 7, 226, 26, 43, 92, 4, 137, 97, 123, 79, 86, 203, 125, 203, 126, 112, 202,
        108, 141, 29, 37, 79, 235, 7, 213, 182, 92, 175, 108, 114, 127, 128, 171, 101, 54, 80, 53,
        5, 19, 53, 70, 179, 173, 78, 144, 56, 64, 208, 253, 46, 110, 199, 116, 56, 246, 96, 89,
        184, 240, 186, 224, 23, 194, 176, 226, 205, 241, 10, 154, 137, 174, 171, 69, 77, 40, 234,
        69, 225, 96, 162, 55, 116, 33, 217, 245, 172, 178, 164, 43, 83, 153, 49, 128, 148, 27, 20,
        162, 210, 162, 233, 97, 213, 223, 155, 127, 187, 53, 43, 63, 55, 8, 112, 83, 215, 92, 152,
        165, 8, 209, 43, 35, 163, 105, 221, 62, 127, 159, 41, 89, 165, 205, 195, 42, 8, 59, 181,
        21, 209, 248, 199, 223, 198, 223, 112, 7, 187, 66, 148, 232, 60, 82, 244, 71, 46, 107, 204,
        86, 90, 14, 228, 162, 110, 86, 160, 25, 205, 78, 115, 136, 176, 78, 236, 182, 74, 57, 208,
        224, 37, 148, 4, 151, 51, 11, 148, 45, 65, 134, 18, 197, 243, 187, 55, 91, 174, 28, 236,
        171, 184, 54, 240, 8, 128, 58, 100, 177, 194, 150, 237, 243, 242, 47, 146, 220, 127, 142,
        179, 27, 201, 101, 26, 32, 31, 112, 170, 124, 175, 71, 117, 32, 214, 255, 124, 80, 141,
        127, 126, 206, 213, 78, 183, 241, 55, 10, 218, 113, 224, 67, 243, 126, 74, 126, 161, 199,
        233, 111, 12, 51, 197, 145, 17, 179, 85, 61, 35, 205, 223, 187, 201, 12, 77, 114, 65, 136,
        66, 73, 116, 100, 15, 223, 141, 181, 244, 71, 81, 72, 15, 117, 134, 109, 184, 208, 125,
        143, 73, 235, 228, 88, 21, 34, 24, 187, 124, 217, 54, 171, 5, 165, 140, 129, 122, 114, 127,
        228, 107, 249, 248, 135, 250, 96, 197, 150, 145, 187, 26, 253, 94, 26, 11, 136, 33, 244,
        225, 110, 29, 191, 150, 131, 172,
    ];

    if data == orig_signature {
        // give the fuzzer a hint this combination is special
        return;
    }

    let signed = Signed {
        content: bstr::BString::new(content.to_vec()),
        signature: data.to_vec(),
    };

    if let Ok(out) = signed.canonicalize(Some(&KEYRING)) {
        if out.len() > 0 {
            panic!("Found valid signature variation");
        }
    }
});
