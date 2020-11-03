package com.ing.dlt.zkkrypto.ecc.schnorr

import java.nio.charset.Charset


object TestVectors {

    val testVectorsPlainMessage = listOf(

        //Message values from Corda EdDSA tests
        TestVector(
            privateKey  = "038cb2eced2553b53133ff70f2d28b6fd4760bf4d4a64bbde4ff5f1e446a6251",
            publicKeyX  = "19e177e8998d7d6a9bba8c0d399b07275da9908d74c5adb36c7a84611e7a7abd",
            publicKeyY  = "10de9f775acede9cd781e13b5205637fd89c557621916bb2fb4c2512fac45c78",
            message     = "",  // empty message
            seed        = "88,91,244,149,205,193,80,4,23,180,91,192,139,202,216,176,208,166,95,177,125,117,195,70,113,211,93,203,182,142,243,109,37,184,56,173,130,97,188,157,162,110,150,170,183,112,208,196,77,136,156,179,129,245,33,12,142,113,151,91,35,82,228,9,28,41,215,22,207,230,69,169,60,159,83,120,188,25,127,121",
            signatureRX = "07b59bcca12d60bb8870c427e30c4a798beaf32fe241ef9989f8c540db5a93dc",
            signatureRY = "20ffb2cf167ca64add9600be6241b7ede765db1a1d55a1c78f1978a6c4113c0b",
            signatureS  = "03cb643f7802037406e7f2d5e11b006f2ea43bd433e6f23a5b040c0584b017d1"
        ),
        TestVector(
            privateKey  = "039a36bb2b19494c1c0fed77f7ddfe73297ef9af33a41653ce0675ea66133b88",
            publicKeyX  = "1266034645de82aa40399d70f590d138e3a687c5dd10d1912baa09804a843365",
            publicKeyY  = "036cf1a11d4cdde482d179582cb0f9393c2935f6db099a1f7070e47cd2dac7da",
            message     = "114", // hex = 72
            seed        = "241,107,170,171,219,102,219,79,229,151,94,185,50,182,251,81,127,126,138,237,52,70,251,59,99,178,9,221,158,98,150,162,171,195,26,168,197,172,180,18,64,109,102,86,160,37,139,141,166,112,208,191,134,223,194,78,234,5,240,47,187,104,48,174,96,210,117,37,171,203,177,37,237,177,177,227,40,218,249,252",
            signatureRX = "2632e529ce386e2a582056c48fc6a082dec26fc4521567163b7afa0fd56ae967",
            signatureRY = "1239365c2e746ba67e93d1a0fd70bd85bb9c4bdb8ac2a2a0c1352f7553123334",
            signatureS  = "034c6ae88222fdc8d33768fed32cdebdc8b9a589d24da0158797af8d8ac9df98"
        ),
        TestVector(
            privateKey  = "025c8c6e1ceb477f5c0cf22b890dc3eac3c9c74a35d45e56744d2297cdc1a93a",
            publicKeyX  = "16f33668fd33167d1143056b2bb8b69d5ffe5c4bdc1a5026e311a125e11a40a6",
            publicKeyY  = "07a3cbb622b1e841ad4438b00bf551b79d20157fba1667839b2151caa1cc8ac1",
            message     = "44930",   // hex = af82
            seed        = "111,138,202,167,181,181,163,122,36,101,151,201,204,243,20,119,82,25,185,94,251,154,72,253,223,80,224,224,166,120,108,193,53,160,71,201,132,63,208,125,4,133,165,133,233,219,90,225,136,3,126,17,112,190,176,193,209,225,2,217,188,65,236,79,124,114,24,161,4,33,74,29,102,198,51,119,24,199,43,151",
            signatureRX = "23d6f4c36141c6967fd01e4fe4acb40697c77c2ebb07fc35e1634212badad626",
            signatureRY = "1dcd19392fa7563c6b8a7eb4aeea797c5b2bba633abda4b388c5c70697488e96",
            signatureS  = "03181ab699c14397c578462c49becf0b821ef87f8461fdd066cf9e81ffd5124d"
        ),

        //Message values from Zinc EdDSA tests
        TestVector(
            privateKey  = "05368b800322fad50e74d9b1eab3364570d67a56ef133de0c8dbf1deaf2a474e",
            publicKeyX  = "2d3801d48de21c009f4329af753cc554793c98c0c9594f4a20f7e7d23608d69d",
            publicKeyY  = "2e55266f6fb271ccd351cbb10cf953adafcafe7c6785375f583611063ddf93cb",
            message     = "Foo bar pad to16", // hex = 466f6f206261722070616420746f3136
            seed        = "134,245,113,236,136,59,19,27,76,5,253,165,115,138,202,147,181,185,14,68,0,165,176,39,22,152,202,206,85,58,80,131,80,99,2,93,106,188,240,108,249,81,18,197,55,120,130,95,243,72,190,98,221,182,232,44,229,198,123,121,83,199,177,46,99,226,37,128,73,201,76,16,97,128,229,135,107,38,14,32",
            signatureRX = "1e28502328d10991706fa7566e753be3c5d63c03f3c22a44f1b9fe7de01468f5",
            signatureRY = "15066772958ad66ac1257bb320eec3878ef542099b94dd0d4abb3c65becffe63",
            signatureS  = "0118041f1d74e9a8488c5a52c51708b733d63b90caadc4990d15fd854e3e6e87"
        ),
        TestVector(
            privateKey  = "01c168e3e5d576d21db750ad9164281118a8cfcdeaf0c1fc9e795ead24311269",
            publicKeyX  = "081df10662923d7a3ab07661d7f84ba719c453a4a25153428feda227ad316db2",
            publicKeyY  = "0c4a7e307278f2aceaab5825d3cb9db9f83d14d4cbb011f531e3af3ddd6b9866",
            message     = "85", // hex = 55
            seed        = "175,64,254,140,185,105,89,5,159,233,108,177,211,223,17,153,223,63,176,233,33,78,147,242,1,166,201,125,198,202,151,214,103,13,36,200,108,181,238,95,241,87,94,192,199,228,203,7,107,133,2,168,114,122,156,48,55,4,7,241,72,75,97,11,12,221,181,118,12,103,110,30,136,57,86,237,23,98,167,52",
            signatureRX = "040d93fcdb43838facdd86f61c1de5776fa37c98fb45c094fd1b62b6730d23ed",
            signatureRY = "2097fd3ba4e104d052a3ba43e90c62453a137dd082ee13da093751212cd9f83f",
            signatureS  = "02f872b014f7b85c21001032f03418e21872dd478cfa8a58b9feaaa0499c08d4"
        )
    )

    val testVectorsHashedMessage = listOf(

        //Message values from Corda EdDSA tests
        TestVector(
            privateKey  = "0221685bd28aba5c2db6e7b56b20dafe00f61f83f174d5d5afaf3aa1c601d97b",
            publicKeyX  = "153a7c3f2f01068a00f69b3f6c5bd9dc1dd7bc9e6a9749a1706e2a3f75269b7d",
            publicKeyY  = "04bcb9b3237cb96a98b89bcf96cc7e9ded03336a9fc4867e3fd0a45a37a77c62",
            message     = "", // empty message
            seed        = "153,132,33,210,245,249,24,102,201,202,138,234,50,193,78,175,239,7,124,243,241,63,88,8,19,68,157,193,201,174,91,66,218,183,146,20,16,197,197,43,234,33,231,171,58,59,193,49,90,198,55,56,206,196,163,107,128,138,48,35,30,135,79,29,76,54,36,34,225,167,61,26,113,72,84,75,160,163,252,195",
            signatureRX = "1b8ff09fb2e74999bdf25f8371e4345dae0ef463c4317c19ba0b75cbf9e0e63b",
            signatureRY = "239481a754cf8b274cec444b7ae6909937927d545cbcf8b463106e85c77f15a3",
            signatureS  = "01c3b69e088c6bcff3eac2b996370a0459cdb7551b4d379997dc6a47ae252a25"
        ),
        TestVector(
            privateKey  = "04fd1a8d01884a505336b038824cb93b28fb9b1bea74cdc8f0b378271990994f",
            publicKeyX  = "2cd65017aa374562cb29873070e3e15dc0c32edff15592354236ae43c131c002",
            publicKeyY  = "1c289a5fa9cf4e75f588f1602c42e7db99dc4e50e68933fdb06b02b13381affc",
            message     = "114",
            seed        = "79,190,111,253,67,76,192,160,166,221,114,125,76,211,238,76,41,125,218,159,73,96,21,121,101,246,226,65,50,28,233,104,183,201,109,24,73,118,56,41,33,68,209,127,197,74,176,7,182,155,181,31,192,164,158,38,193,204,11,96,218,60,132,180,210,197,17,223,129,157,40,10,28,113,103,40,44,101,185,62",
            signatureRX = "0fcfcb5dc87336c22864d04df03f5469337164b3ad5c4e46e508b7036e6f73b0",
            signatureRY = "0141648c840ed67ed068fa08d55bd41afa4627e2fdd189c281d71b3fbb55c81b",
            signatureS  = "053c4f71fdb4a0410bbb06d2ca4f57223a5420b0d769031d3e66b8ffd6f61af7"
        ),
        TestVector(
            privateKey  = "001dd6fc631336f133c2080b29f8fe9c7d6a23bc8a65a0421a47490402ef94e1",
            publicKeyX  = "0fc4a18ac3079e2e29592637078c0a2f4e2d049e550cf77d14feaf0b715abc01",
            publicKeyY  = "148ae1ac557c1eb2aa0d5f5761c9133520632a7340745e5f4079b6e14de36c4b",
            message     = "44930",
            seed        = "43,128,86,219,211,163,3,4,172,151,115,34,168,178,86,174,40,229,188,154,226,197,13,5,153,123,214,13,143,128,29,122,86,31,248,204,116,175,205,139,190,157,54,215,150,55,159,212,154,120,230,56,122,182,149,143,23,232,31,22,63,124,249,34,56,190,11,236,123,204,50,192,109,42,150,84,162,183,49,108",
            signatureRX = "15aac870d3ca8f2f5532be509231253d0ec8368b7ab800f1cf464d78cebe97a5",
            signatureRY = "1852f2d83de46c3c0c852a710ca528653d4c2e025e2adab5883e96852acf996e",
            signatureS  = "04fb958b6e923fa17540400e5b273ee9be27e90359e750b1e4bf1ef0602a3d71"
        ),
        //Message values from Zinc EdDSA tests
        TestVector(
            privateKey  = "05368b800322fad50e74d9b1eab3364570d67a56ef133de0c8dbf1deaf2a474e",
            publicKeyX  = "2d3801d48de21c009f4329af753cc554793c98c0c9594f4a20f7e7d23608d69d",
            publicKeyY  = "2e55266f6fb271ccd351cbb10cf953adafcafe7c6785375f583611063ddf93cb",
            message     = "Foo bar pad to16",
            seed        = "134,245,113,236,136,59,19,27,76,5,253,165,115,138,202,147,181,185,14,68,0,165,176,39,22,152,202,206,85,58,80,131,80,99,2,93,106,188,240,108,249,81,18,197,55,120,130,95,243,72,190,98,221,182,232,44,229,198,123,121,83,199,177,46,99,226,37,128,73,201,76,16,97,128,229,135,107,38,14,32",
            signatureRX = "1e28502328d10991706fa7566e753be3c5d63c03f3c22a44f1b9fe7de01468f5",
            signatureRY = "15066772958ad66ac1257bb320eec3878ef542099b94dd0d4abb3c65becffe63",
            signatureS  = "00ae07f728917c50fcfbe11f9946baa3851cfc410698069ed157b5704f1f2e08"
        ),
        TestVector(
            privateKey  = "00b647a4a9faad77d1cc52f9dc3d103b79439399d4ff7effd073dd25d3fec3bc",
            publicKeyX  = "27fb8e130f0bf2cf48af0cad462f0b8b9882ceb6b04198af9b03822c66f66226",
            publicKeyY  = "2232246bcd1968cef89508e65fe8a670005b1e55265f8b2e0cc9c1ca218d7407",
            message     = "85",
            seed        = "86,90,37,124,65,244,182,229,141,100,56,54,103,190,64,25,176,96,100,19,229,232,117,65,68,57,133,20,77,170,71,99,48,107,36,251,142,102,87,146,83,11,12,60,9,74,210,123,99,246,40,143,96,254,19,65,124,10,69,32,93,47,239,193,224,183,31,49,149,80,201,110,171,192,244,132,57,235,193,235",
            signatureRX = "26de31489e9f36b11845d8aa96055f7af23184daea613adf1916bd12a270f1c0",
            signatureRY = "16c0422abf353dd7b51d8143c1d36fc5feaefe61c127ad125066409b827559f9",
            signatureS  = "04357e3a31baa5f846dc6bb7113f2d9c068977d2481c82d263f6e9535ab75743"
        )
    )

    data class TestVector(
        val privateKey: String,
        val publicKeyX: String,
        val publicKeyY: String,
        val message: String,
        val seed: String,
        val signatureRX: String,
        val signatureRY: String,
        val signatureS: String
    )
}