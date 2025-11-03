use crate::{Field, OptionalPostalAddress, ValidationError, email::Email};

use super::IdentityType;

pub fn validate_create_identity(
    t: IdentityType,
    email: &Option<Email>,
    postal_address: &OptionalPostalAddress,
) -> Result<(), ValidationError> {
    if let IdentityType::Ident = t {
        // email needs to be set and not blank
        if email.is_none() {
            return Err(ValidationError::FieldEmpty(Field::Email));
        }
        // For Ident, the postal address needs to be fully set
        postal_address.validate_to_be_non_optional()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OptionalPostalAddress, identity::IdentityType, tests::tests::valid_optional_address,
    };
    use rstest::rstest;

    #[test]
    fn test_validate_create_identity() {
        let result =
            validate_create_identity(IdentityType::Anon, &None, &OptionalPostalAddress::empty());
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::ident_no_email(IdentityType::Ident, &None, &valid_optional_address(), ValidationError::FieldEmpty(Field::Email))]
    fn test_validate_create_identity_errors(
        #[case] t: IdentityType,
        #[case] email: &Option<Email>,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_create_identity(t, email, postal_address,),
            Err(expected)
        );
    }
}
