use crate::service::ServiceContext;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;

pub struct IdentityCheck;

#[derive(Debug)]
pub struct IdentityCheckError;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IdentityCheck {
    type Error = Status;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let path = request.uri().path();

        if path.starts_with("/identity") {
            return Outcome::Success(IdentityCheck);
        }

        if let Some(context) = request.rocket().state::<ServiceContext>() {
            if !context.identity_service.identity_exists().await {
                return Outcome::Error((Status::NotAcceptable, Status::NotAcceptable));
            }
        } else {
            return Outcome::Error((Status::NotAcceptable, Status::NotAcceptable));
        }

        Outcome::Success(IdentityCheck)
    }
}
