use crate::{ValidationError, constants::VALID_CURRENCIES};

pub fn parse_sum(sum: &str) -> Result<u64, ValidationError> {
    match sum.parse::<u64>() {
        Ok(num) => Ok(num),
        Err(_) => Err(ValidationError::InvalidSum),
    }
}

pub fn validate_sum(sum: u64) -> Result<(), ValidationError> {
    if sum == 0 {
        return Err(ValidationError::InvalidSum);
    }
    Ok(())
}

pub fn sum_to_string(sum: u64) -> String {
    sum.to_string()
}

pub fn sat_to_btc(val: u64) -> String {
    let amount = bitcoin::Amount::from_sat(val);
    amount.to_string_in(bitcoin::Denomination::Bitcoin)
}

pub fn validate_currency(currency: &str) -> Result<(), ValidationError> {
    if !VALID_CURRENCIES.contains(&currency.to_lowercase().as_str()) {
        return Err(ValidationError::InvalidCurrency);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sat_to_btc_test() {
        assert_eq!(sat_to_btc(1000), String::from("0.00001"));
        assert_eq!(sat_to_btc(10000), String::from("0.0001"));
        assert_eq!(sat_to_btc(1), String::from("0.00000001"));
    }
}
