//! Mathematical domain data, not runtime parsers or mutable caches.
//!
//! Coefficients/orders: DSTU4145-2002 annex D (original Cyrillic G).
//! Polynomial base points agree with Bouncy Castle `DSTU4145NamedCurves`.
//! Normal-basis coefficients and base points agree with UAPKI's published
//! ec-default-params.c. Isomorphic Frobenius images are not substituted.
//! <https://github.com/specinfo-ua/UAPKI/blob/a407504f670a4a2f3055c7c7773852fe4ab2cf4c/library/uapkic/src/ec-default-params.c>

use crate::{Basis, words::Words};

pub(crate) struct Spec {
    pub(crate) m: usize,
    pub(crate) a: bool,
    pub(crate) b: Words,
    pub(crate) order: Words,
    pub(crate) x: Words,
    pub(crate) y: Words,
}

pub(crate) const POLYNOMIALS: [[usize; 4]; 60] = [
    [163, 3, 6, 7],
    [167, 6, 0, 0],
    [173, 1, 2, 10],
    [179, 1, 2, 4],
    [181, 1, 6, 7],
    [191, 9, 0, 0],
    [193, 15, 0, 0],
    [197, 1, 2, 21],
    [199, 1, 2, 11],
    [211, 1, 6, 12],
    [223, 1, 2, 12],
    [227, 1, 2, 21],
    [229, 1, 2, 21],
    [233, 1, 4, 9],
    [239, 1, 2, 15],
    [241, 1, 4, 15],
    [251, 1, 4, 14],
    [257, 12, 0, 0],
    [263, 1, 2, 27],
    [269, 1, 6, 7],
    [271, 1, 3, 16],
    [277, 2, 3, 23],
    [281, 1, 4, 9],
    [283, 1, 9, 26],
    [293, 1, 6, 11],
    [307, 2, 4, 8],
    [311, 1, 4, 29],
    [313, 1, 3, 7],
    [317, 2, 5, 9],
    [331, 2, 5, 12],
    [337, 1, 6, 10],
    [347, 1, 6, 17],
    [349, 2, 5, 6],
    [353, 3, 7, 26],
    [359, 2, 4, 18],
    [367, 21, 0, 0],
    [373, 1, 6, 9],
    [379, 1, 6, 17],
    [383, 1, 5, 9],
    [389, 1, 10, 17],
    [397, 1, 3, 22],
    [401, 1, 4, 29],
    [409, 1, 6, 15],
    [419, 1, 14, 21],
    [421, 1, 4, 7],
    [431, 1, 3, 5],
    [433, 1, 5, 15],
    [439, 2, 3, 8],
    [443, 1, 3, 28],
    [449, 3, 5, 25],
    [457, 16, 0, 0],
    [461, 1, 4, 23],
    [463, 1, 3, 24],
    [467, 1, 3, 28],
    [479, 1, 6, 25],
    [487, 1, 2, 15],
    [491, 2, 6, 17],
    [499, 2, 6, 29],
    [503, 3, 0, 0],
    [509, 2, 3, 23],
];

pub(crate) fn named(basis: Basis, degree: usize) -> Option<&'static Spec> {
    let specs = match basis {
        Basis::Polynomial => &PB[..],
        Basis::OptimalNormal => &ONB[..],
    };
    specs.iter().find(|spec| spec.m == degree)
}

pub(crate) static PB: [Spec; 10] = [
    Spec {
        m: 163,
        a: true,
        b: Words::hex("5FF6108462A2DC8210AB403925E638A19C1455D21"),
        order: Words::hex("400000000000000000002BEC12BE2262D39BCF14D"),
        x: Words::hex("2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE"),
        y: Words::hex("3826F008A8C51D7B95284D9D03FF0E00CE2CD723A"),
    },
    Spec {
        m: 167,
        a: true,
        b: Words::hex("6EE3CEEB230811759F20518A0930F1A4315A827DAC"),
        order: Words::hex("3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F"),
        x: Words::hex("7A1F6653786A68192803910A3D30B2A2018B21CD54"),
        y: Words::hex("5F49EB26781C0EC6B8909156D98ED435E45FD59918"),
    },
    Spec {
        m: 173,
        a: false,
        b: Words::hex("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9"),
        order: Words::hex("800000000000000000000189B4E67606E3825BB2831"),
        x: Words::hex("4D41A619BCC6EADF0448FA22FAD567A9181D37389CA"),
        y: Words::hex("10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1"),
    },
    Spec {
        m: 179,
        a: true,
        b: Words::hex("4A6E0856526436F2F88DD07A341E32D04184572BEB710"),
        order: Words::hex("3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF"),
        x: Words::hex("6BA06FE51464B2BD26DC57F48819BA9954667022C7D03"),
        y: Words::hex("25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E"),
    },
    Spec {
        m: 191,
        a: true,
        b: Words::hex("7BC86E2102902EC4D5890E8B6B4981FF27E0482750FEFC03"),
        order: Words::hex("40000000000000000000000069A779CAC1DABC6788F7474F"),
        x: Words::hex("714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129"),
        y: Words::hex("29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA"),
    },
    Spec {
        m: 233,
        a: true,
        b: Words::hex("06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C"),
        order: Words::hex("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7"),
        x: Words::hex("3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96"),
        y: Words::hex("9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35"),
    },
    Spec {
        m: 257,
        a: false,
        b: Words::hex("1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10"),
        order: Words::hex("800000000000000000000000000000006759213AF182E987D3E17714907D470D"),
        x: Words::hex("02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7"),
        y: Words::hex("10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF"),
    },
    Spec {
        m: 307,
        a: true,
        b: Words::hex(
            "393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB",
        ),
        order: Words::hex(
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7",
        ),
        x: Words::hex(
            "216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA",
        ),
        y: Words::hex(
            "5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0",
        ),
    },
    Spec {
        m: 367,
        a: true,
        b: Words::hex(
            "43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136",
        ),
        order: Words::hex(
            "40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49",
        ),
        x: Words::hex(
            "324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1",
        ),
        y: Words::hex(
            "1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10",
        ),
    },
    Spec {
        m: 431,
        a: true,
        b: Words::hex(
            "03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3",
        ),
        order: Words::hex(
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
        ),
        x: Words::hex(
            "1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D",
        ),
        y: Words::hex(
            "70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9",
        ),
    },
];

pub(crate) static ONB: [Spec; 5] = [
    Spec {
        m: 173,
        a: false,
        b: Words::hex("043D7E139319F43BA00944915740E1E6651B06E278C7"),
        order: Words::hex("800000000000000000000189B4E67606E3825BB2831"),
        x: Words::hex("0A3B8B8D704089B24318CAA51917CB6E424B4E6DEA56"),
        y: Words::hex("005A43D5EE1F400349CF35150C74F119A39145F0CB08"),
    },
    Spec {
        m: 179,
        a: true,
        b: Words::hex("19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB"),
        order: Words::hex("3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF"),
        x: Words::hex("11F4112265410477159E0D3E39BC4AC4ADE43B21B66B9"),
        y: Words::hex("2CA5F0B34C61A86216F13766591CB266E2819EE582B3C"),
    },
    Spec {
        m: 191,
        a: true,
        b: Words::hex("13871C9D29D6CEEA740FD57444F72FDBAE559C13A1E31EF8"),
        order: Words::hex("40000000000000000000000069A779CAC1DABC6788F7474F"),
        x: Words::hex("7159E0D3E39BC4AC4ADE43B21B66B94F2AF25ABEEB1D85D3"),
        y: Words::hex("57E45D546BE6201E9705E029535D009D31F51D81E18226BE"),
    },
    Spec {
        m: 233,
        a: true,
        b: Words::hex("080F920952A702C75B704A424C018EEA55AA44664F3A003E0962D4F9A8E"),
        order: Words::hex("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7"),
        x: Words::hex("0A0823B8ACF069F1CDE256256F21D90DB35CA795792D5F758EC2E9992FB"),
        y: Words::hex("19DAE222AF326D33AFB7761953F624A23D3EB1CA7A1C300F0AA9953CA85"),
    },
    Spec {
        m: 431,
        a: true,
        b: Words::hex(
            "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299",
        ),
        order: Words::hex(
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
        ),
        x: Words::hex(
            "2020182CFCD7C724157B363D4ABFD4C16251773C595D4E5C88572FA9D5EBB58142326448C08D3EE3E17E40B835D3090DCFBA7C5ADEA6",
        ),
        y: Words::hex(
            "18E1B6EFB28EEF8A1F9C1859ED57C74CA747E4E1A60294C005D1920E80903A432929855828DD7F21714F837E119A044987F00110ADAD",
        ),
    },
];
