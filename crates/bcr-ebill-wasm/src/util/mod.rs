use std::iter::successors;

const ONES: [&str; 20] = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
];
const TENS: [&str; 10] = [
    "zero", "ten", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
];
const ORDERS: [&str; 7] = [
    "zero",
    "thousand",
    "million",
    "billion",
    "trillion",
    "quadrillion",
    "quintillion",
];

pub fn numbers_to_words(num: &u64) -> String {
    match num {
        0..=19 => ONES[*num as usize].to_string(),
        20..=99 => {
            let upper: usize = (num / 10) as usize;
            match num % 10 {
                0 => TENS[upper].to_string(),
                lower => format!("{}-{}", TENS[upper], numbers_to_words(&lower)),
            }
        }
        100..=999 => format_num(num, 100, "hundred"),
        _ => {
            let (div, order) = successors(Some(1u64), |v| v.checked_mul(1000))
                .zip(ORDERS.iter())
                .find(|&(e, _)| e > num / 1000)
                .expect("it's a valid number");

            format_num(num, div, order)
        }
    }
}

fn format_num(num: &u64, div: u64, order: &str) -> String {
    match (num / div, num % div) {
        (upper, 0) => format!("{} {}", numbers_to_words(&upper), order),
        (upper, lower) => {
            format!(
                "{} {} {}",
                numbers_to_words(&upper),
                order,
                numbers_to_words(&lower)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_to_letters_one() {
        let result = numbers_to_words(&5);
        assert_eq!("five".to_string(), result);
    }

    #[test]
    fn numbers_to_letters_zero() {
        let result = numbers_to_words(&0);
        assert_eq!("zero".to_string(), result);
    }

    #[test]
    fn numbers_to_letters_few() {
        let result = numbers_to_words(&999);
        assert_eq!("nine hundred ninety-nine".to_string(), result);
    }

    #[test]
    fn numbers_to_letters_many() {
        let result = numbers_to_words(&123_324_324);
        assert_eq!("one hundred twenty-three million three hundred twenty-four thousand three hundred twenty-four".to_string(), result);
    }
}
