// SQL
pub(crate) const UPSERT: &str = r#"
    INSERT INTO email_notifications (
        node_id,
        email_preferences_link
    )
    VALUES ($1, $2)
    ON CONFLICT(node_id) DO UPDATE SET
        email_preferences_link = excluded.email_preferences_link
"#;

pub(crate) const SELECT_LINK: &str = r#"
    SELECT email_preferences_link
    FROM email_notifications
    WHERE node_id = $1
"#;
