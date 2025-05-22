use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};

use crate::ValidationError;

pub type DateTimeUtc = DateTime<Utc>;
pub const DEFAULT_DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
pub const DEFAULT_DATE_FORMAT: &str = "%Y-%m-%d";

/// Returns the current time as DateTime
pub fn now() -> DateTimeUtc {
    Utc::now()
}

/// Quickly create a DateTimeUtc from a timestamp. chrono does not
/// really use Results and most of the errors are super unlikely to
/// happen.
pub fn seconds(timestamp: u64) -> DateTimeUtc {
    match Utc.timestamp_opt(timestamp as i64, 0).single() {
        Some(dt) => dt,
        None => panic!("invalid timestamp"),
    }
}

/// Returns the start of day timestamp for the given timestamp
pub fn start_of_day_as_timestamp(timestamp: u64) -> u64 {
    let dt = seconds(timestamp);
    let date = dt.date_naive();
    let end_of_day_time =
        NaiveTime::from_hms_micro_opt(00, 00, 00, 000_000).expect("is a valid time");
    let date_time = date.and_time(end_of_day_time);
    let date_utc = Utc.from_utc_datetime(&date_time);
    date_utc.timestamp() as u64
}

/// Returns the end of day timestamp for the given timestamp
pub fn end_of_day_as_timestamp(timestamp: u64) -> u64 {
    let dt = seconds(timestamp);
    let date = dt.date_naive();
    let end_of_day_time =
        NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).expect("is a valid time");
    let date_time = date.and_time(end_of_day_time);
    let date_utc = Utc.from_utc_datetime(&date_time);
    date_utc.timestamp() as u64
}

/// Converts the given date string (default format) to rfc3339
pub fn date_string_to_rfc3339(date_str: &str) -> Result<String, ValidationError> {
    let naive_date_time = NaiveDate::parse_from_str(date_str, DEFAULT_DATE_FORMAT)
        .map_err(|_| ValidationError::InvalidDate)?
        .and_hms_opt(0, 0, 0)
        .ok_or(ValidationError::InvalidDate)?;
    let date_utc = Utc.from_utc_datetime(&naive_date_time);

    Ok(date_utc.to_rfc3339())
}

/// Returns the timestamp for the given date string, with the time set to the start of day
pub fn date_string_to_timestamp(
    date_str: &str,
    format_str: Option<&str>,
) -> Result<u64, ValidationError> {
    let format = format_str.unwrap_or(DEFAULT_DATE_FORMAT);

    let naive_date_time = NaiveDate::parse_from_str(date_str, format)
        .map_err(|_| ValidationError::InvalidDate)?
        .and_hms_opt(0, 0, 0)
        .ok_or(ValidationError::InvalidDate)?;
    let date_utc = Utc.from_utc_datetime(&naive_date_time);

    Ok(date_utc.timestamp() as u64)
}

pub fn format_date_string(date: DateTimeUtc) -> String {
    date.format(DEFAULT_DATE_FORMAT).to_string()
}

/// checks if the given timestamp plus the given deadline is after the given current timestamp
pub fn check_if_deadline_has_passed(
    timestamp_to_check: u64,
    current_timestamp: u64,
    deadline_seconds: u64,
) -> bool {
    // We check this to avoid a u64 underflow, if the block timestamp is in the future, the
    // deadline can't be expired
    if timestamp_to_check > current_timestamp {
        return false;
    }
    let difference = current_timestamp - timestamp_to_check;
    difference > deadline_seconds
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use chrono::Utc;

    #[test]
    fn test_now() {
        let now = now().timestamp();
        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            now >= timestamp - 1,
            "now date was {} seconds smaller than expected",
            (timestamp - now)
        );
    }

    #[test]
    fn test_start_of_day() {
        let ts = Utc
            .with_ymd_and_hms(2025, 1, 15, 5, 10, 45)
            .unwrap()
            .timestamp() as u64;
        let start_of_day = start_of_day_as_timestamp(ts);
        assert!(start_of_day < ts,);
    }

    #[test]
    fn test_end_of_day() {
        let ts = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        let end_of_day = end_of_day_as_timestamp(ts);
        assert!(end_of_day > ts,);
    }

    #[test]
    fn test_date_string_to_timestamp_with_default_format() {
        let date_str = "2025-01-15";
        let expected_timestamp = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        assert_eq!(
            date_string_to_timestamp(date_str, None).unwrap(),
            expected_timestamp
        );
    }

    #[test]
    fn test_date_string_to_timestamp_with_custom_format() {
        let date_str = "15/01/2025";
        let expected_timestamp = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        assert_eq!(
            date_string_to_timestamp(date_str, Some("%d/%m/%Y")).unwrap(),
            expected_timestamp
        );
    }

    #[test]
    fn test_date_string_to_timestamp_with_invalid_date() {
        assert!(date_string_to_timestamp("2025-32-99", None).is_err());
        assert!(date_string_to_timestamp("2025/01/15", None).is_err());
        assert!(date_string_to_timestamp("", None).is_err());
    }

    #[test]
    fn test_date_string_to_rfc3339() {
        let date_str = "2025-01-15";
        let expected_timestamp = "2025-01-15T00:00:00+00:00";
        assert_eq!(
            date_string_to_rfc3339(date_str).unwrap(),
            expected_timestamp
        );
    }

    #[test]
    fn test_date_string_to_rfc3339_invalid_data() {
        assert!(date_string_to_rfc3339("2025-32-99").is_err());
        assert!(date_string_to_rfc3339("2025/01/15").is_err());
        assert!(date_string_to_rfc3339("").is_err());
    }
}
