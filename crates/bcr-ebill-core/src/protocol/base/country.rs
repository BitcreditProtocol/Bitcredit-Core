use std::str::FromStr;

use strum::{Display, EnumString};

use crate::protocol::ProtocolValidationError;

#[derive(Debug, Clone, EnumString, Display, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
pub enum Country {
    AF,
    AL,
    DZ,
    AS,
    AD,
    AO,
    AI,
    AQ,
    AG,
    AR,
    AM,
    AW,
    AU,
    AT,
    AZ,
    BS,
    BH,
    BD,
    BB,
    BY,
    BE,
    BZ,
    BJ,
    BM,
    BT,
    BO,
    BA,
    BW,
    BR,
    BN,
    BG,
    BF,
    BI,
    CV,
    KH,
    CM,
    CA,
    KY,
    CF,
    TD,
    CL,
    CN,
    CO,
    KM,
    CG,
    CD,
    CR,
    CI,
    HR,
    CU,
    CY,
    CZ,
    DK,
    DJ,
    DM,
    DO,
    EC,
    EG,
    SV,
    GQ,
    ER,
    EE,
    SZ,
    ET,
    FJ,
    FI,
    FR,
    GA,
    GM,
    GE,
    DE,
    GH,
    GR,
    GL,
    GD,
    GU,
    GT,
    GN,
    GW,
    GY,
    HT,
    HN,
    HU,
    IS,
    IN,
    ID,
    IR,
    IQ,
    IE,
    IL,
    IT,
    JM,
    JP,
    JO,
    KZ,
    KE,
    KI,
    KP,
    KR,
    KW,
    KG,
    LA,
    LV,
    LB,
    LS,
    LR,
    LY,
    LI,
    LT,
    LU,
    MG,
    MW,
    MY,
    MV,
    ML,
    MT,
    MH,
    MR,
    MU,
    MX,
    FM,
    MD,
    MC,
    MN,
    ME,
    MA,
    MZ,
    MM,
    NA,
    NR,
    NP,
    NL,
    NZ,
    NI,
    NE,
    NG,
    NO,
    OM,
    PK,
    PW,
    PS,
    PA,
    PG,
    PY,
    PE,
    PH,
    PL,
    PT,
    QA,
    RO,
    RU,
    RW,
    WS,
    SM,
    ST,
    SA,
    SN,
    RS,
    SC,
    SL,
    SG,
    SK,
    SI,
    SB,
    SO,
    ZA,
    SS,
    ES,
    LK,
    SD,
    SR,
    SE,
    CH,
    SY,
    TW,
    TJ,
    TZ,
    TH,
    TL,
    TG,
    TO,
    TT,
    TN,
    TR,
    TM,
    TV,
    UG,
    UA,
    AE,
    GB,
    US,
    UY,
    UZ,
    VU,
    VA,
    VE,
    VN,
    YE,
    ZM,
    ZW,
}

impl Country {
    pub fn is_valid_country(country: &str) -> bool {
        Country::parse(country).is_ok()
    }

    pub fn parse(country: &str) -> Result<Self, ProtocolValidationError> {
        Country::from_str(country).map_err(|_| ProtocolValidationError::InvalidCountry)
    }
}

impl serde::Serialize for Country {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Country {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Country::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl borsh::BorshSerialize for Country {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let country_str = self.to_string();
        borsh::BorshSerialize::serialize(&country_str, writer)
    }
}

impl borsh::BorshDeserialize for Country {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let country_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Country::from_str(&country_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        borsh_derive::BorshSerialize,
        borsh_derive::BorshDeserialize,
        Serialize,
        Deserialize,
    )]
    pub struct TestCountry {
        pub country: Country,
    }

    #[test]
    fn test_serialization() {
        let country = Country::AT;
        let test = TestCountry {
            country: country.clone(),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"country\":\"AT\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(country, deserialized.country);

        let borsh = borsh::to_vec(&country).unwrap();
        let borsh_de = Country::try_from_slice(&borsh).unwrap();
        assert_eq!(country, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestCountry::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(country, borsh_de_test.country);
    }

    #[test]
    fn test_invalid_serialization() {
        let json = "{\"country\":\"\"}";
        let deserialized = serde_json::from_str::<TestCountry>(json);
        assert!(deserialized.is_err());

        let borsh = borsh::to_vec(&String::from("")).expect("works");
        let res = Country::try_from_slice(&borsh);
        assert!(res.is_err());

        let borsh = borsh::to_vec(&String::from("AT")).expect("works");
        let res = Country::try_from_slice(&borsh);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_countries() {
        assert!(Country::is_valid_country("at"));
        assert!(Country::is_valid_country("At"));
        assert!(Country::is_valid_country("aT"));
        assert!(Country::is_valid_country("AT"));
        assert!(!Country::is_valid_country("WHAT?NOTHISISNOCOUNTRY"));
        assert_eq!(&Country::AT.to_string(), "AT");
    }
}
