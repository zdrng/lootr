//! Calendar dates and timestamps without a date library: waiver expiry needs
//! a UTC date, the report needs an RFC 3339 timestamp, JWT attributes need
//! hour differences. The conversion is
//! Howard Hinnant's `civil_from_days` / `days_from_civil`.

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_HOUR: i64 = 3_600;

/// Whole hours from Unix time `from` to `to`, rounded towards negative
/// infinity (`-0.5 h` is `-1`), so anything in the past is negative.
pub fn hours_between(from: i64, to: i64) -> i64 {
    to.saturating_sub(from).div_euclid(SECONDS_PER_HOUR)
}

/// A UTC calendar date. Ordered chronologically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: i32,
    month: u8,
    day: u8,
}

impl Date {
    /// `None` for impossible dates (`2026-02-30`).
    pub fn new(year: i32, month: u8, day: u8) -> Option<Date> {
        let date = Date { year, month, day };
        let valid = (1..=12).contains(&month)
            && day >= 1
            && Date::from_days(date.days_since_epoch()) == date;
        valid.then_some(date)
    }

    /// The UTC date of a Unix timestamp.
    pub fn from_unix(seconds: i64) -> Date {
        Date::from_days(seconds.div_euclid(SECONDS_PER_DAY))
    }

    /// Days from `self` to `other` (negative if `other` is earlier).
    pub fn days_until(self, other: Date) -> i64 {
        other.days_since_epoch() - self.days_since_epoch()
    }

    fn from_days(days: i64) -> Date {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
        Date { year, month, day }
    }

    fn days_since_epoch(self) -> i64 {
        let y = i64::from(self.year) - i64::from(self.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let m = i64::from(self.month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl FromStr for Date {
    type Err = String;
    /// `YYYY-MM-DD`.
    fn from_str(s: &str) -> Result<Date, String> {
        let err = || format!("`{s}` is not a date (YYYY-MM-DD)");
        let mut parts = s.splitn(3, '-');
        let mut next = || parts.next().ok_or_else(err);
        let (y, m, d) = (next()?, next()?, next()?);
        if y.len() != 4 || m.len() != 2 || d.len() != 2 {
            return Err(err());
        }
        let num = |p: &str| p.parse::<u16>().map_err(|_| err());
        let year = i32::from(num(y)?);
        let (month, day) = (num(m)?, num(d)?);
        let (Ok(month), Ok(day)) = (u8::try_from(month), u8::try_from(day)) else {
            return Err(err());
        };
        Date::new(year, month, day).ok_or_else(err)
    }
}

impl Serialize for Date {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// `2026-10-08T14:03:00Z` for a Unix timestamp.
pub fn rfc3339(seconds: i64) -> String {
    let date = Date::from_unix(seconds);
    let secs = seconds.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_to_date() {
        assert_eq!(Date::from_unix(0).to_string(), "1970-01-01");
        assert_eq!(Date::from_unix(951_782_400).to_string(), "2000-02-29");
        assert_eq!(Date::from_unix(1_791_468_180).to_string(), "2026-10-08");
        assert_eq!(Date::from_unix(-1).to_string(), "1969-12-31");
    }

    #[test]
    fn parse_and_validate() {
        assert_eq!(
            "2027-01-31".parse::<Date>().unwrap().to_string(),
            "2027-01-31"
        );
        assert!("2026-02-29".parse::<Date>().is_err());
        assert!("2024-02-29".parse::<Date>().is_ok());
        assert!("2026-13-01".parse::<Date>().is_err());
        assert!("26-01-01".parse::<Date>().is_err());
        assert!("2026-1-01".parse::<Date>().is_err());
        assert!("2026-01-01x".parse::<Date>().is_err());
    }

    #[test]
    fn ordering() {
        let a: Date = "2026-12-31".parse().unwrap();
        let b: Date = "2027-01-01".parse().unwrap();
        assert!(a < b);
        assert_eq!(a.days_until(b), 1);
        assert_eq!(b.days_until(a), -1);
        let c: Date = "2028-01-01".parse().unwrap();
        assert_eq!(b.days_until(c), 365);
    }

    #[test]
    fn hours() {
        assert_eq!(hours_between(0, 7_200), 2);
        assert_eq!(hours_between(0, 7_199), 1);
        assert_eq!(hours_between(1_800, 0), -1);
        assert_eq!(hours_between(i64::MIN, i64::MAX), i64::MAX / 3_600);
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_791_468_180), "2026-10-08T14:03:00Z");
    }
}
