use crate::{
    Result,
    sql::{
        notification::{
            DELETE_NOTIFICATION, INSERT_NOTIFICATION, INSERT_SENT_NOTIFICATION,
            MARK_NOTIFICATION_DONE, NotificationRow, SELECT_NOTIFICATION_BASE,
            SELECT_NOTIFICATION_EVENT_EXISTS, SELECT_SENT_NOTIFICATION_EXISTS, action_type_to_db,
            notification_to_row, notification_type_to_db,
        },
        timestamp_to_db,
    },
    traits::notification::{NotificationFilter, NotificationStoreApi},
};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::{
        ServiceTraitBounds,
        notification::{Notification, NotificationType},
    },
    protocol::{Timestamp, event::bill_events::ActionType},
};
use sqlx::{PgPool, Postgres, QueryBuilder, types::Text};
use std::collections::{HashMap, hash_map::Entry};

#[derive(Clone)]
pub struct PostgresNotificationStore {
    pool: PgPool,
}

impl PostgresNotificationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresNotificationStore {}

#[async_trait]
impl NotificationStoreApi for PostgresNotificationStore {
    async fn get_active_status_for_node_ids(
        &self,
        node_ids: &[NodeId],
    ) -> Result<HashMap<NodeId, bool>> {
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT DISTINCT node_id FROM notifications WHERE active = ",
        );
        query.push_bind(true);
        query.push(" AND node_id IS NOT NULL");
        if !node_ids.is_empty() {
            query.push(" AND node_id IN (");
            {
                let mut separated = query.separated(", ");
                for node_id in node_ids {
                    separated.push_bind(node_id.to_string());
                }
            }
            query.push(")");
        }
        let active: Vec<Text<NodeId>> = query.build_query_scalar().fetch_all(&self.pool).await?;
        let active: Vec<NodeId> = active.into_iter().map(Text::into_inner).collect();
        if node_ids.is_empty() {
            return Ok(active.into_iter().map(|node_id| (node_id, true)).collect());
        }
        Ok(node_ids
            .iter()
            .cloned()
            .map(|node_id| {
                let is_active = active.contains(&node_id);
                (node_id, is_active)
            })
            .collect())
    }

    async fn add(&self, notification: Notification) -> Result<Notification> {
        let row = notification_to_row(notification)?;
        let result = Notification::try_from(row.clone())?;
        sqlx::query(INSERT_NOTIFICATION)
            .bind(row.id)
            .bind(row.node_id)
            .bind(row.notification_type)
            .bind(row.reference_id)
            .bind(row.description)
            .bind(row.datetime)
            .bind(row.active)
            .bind(row.level)
            .bind(row.payload)
            .bind(row.event_id)
            .execute(&self.pool)
            .await?;
        Ok(result)
    }

    async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>> {
        let mut query =
            QueryBuilder::<Postgres>::new(format!("{SELECT_NOTIFICATION_BASE} WHERE 1 = 1"));
        if let Some(active) = filter.get_active() {
            query.push(" AND active = ");
            query.push_bind(active.1);
        }
        if let Some(reference_id) = filter.get_reference_id() {
            query.push(" AND reference_id = ");
            query.push_bind(reference_id.1.to_owned());
        }
        if let Some(notification_type) = filter.get_notification_type() {
            query.push(" AND notification_type = ");
            query.push_bind(notification_type.1.to_owned());
        }
        if let Some(event_id) = filter.get_event_id() {
            query.push(" AND event_id = ");
            query.push_bind(event_id.1.to_owned());
        }
        if let Some(node_ids) = filter.get_node_ids() {
            if node_ids.1.is_empty() {
                return Ok(vec![]);
            }
            query.push(" AND node_id IN (");
            {
                let mut separated = query.separated(", ");
                for node_id in node_ids.1 {
                    separated.push_bind(node_id.to_string());
                }
            }
            query.push(")");
        }
        if let Some(level) = filter.get_level() {
            query.push(" AND level = ");
            query.push_bind(level.1.to_owned());
        }
        query.push(" ORDER BY datetime DESC");
        query.push(" LIMIT ");
        query.push_bind(filter.get_limit());
        query.push(" OFFSET ");
        query.push_bind(filter.get_offset());
        let rows: Vec<NotificationRow> = query.build_query_as().fetch_all(&self.pool).await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_latest_by_references(
        &self,
        references: &[String],
        notification_type: NotificationType,
    ) -> Result<HashMap<String, Notification>> {
        if references.is_empty() {
            return Ok(HashMap::new());
        }
        let mut query = QueryBuilder::<Postgres>::new(SELECT_NOTIFICATION_BASE);
        query.push(" WHERE active = ");
        query.push_bind(true);
        query.push(" AND notification_type = ");
        query.push_bind(notification_type_to_db(&notification_type));
        query.push(" AND reference_id IN (");
        {
            let mut separated = query.separated(", ");
            for reference in references {
                separated.push_bind(reference);
            }
        }
        query.push(")");
        let rows: Vec<NotificationRow> = query.build_query_as().fetch_all(&self.pool).await?;
        let mut result = HashMap::new();
        for row in rows {
            let notification = Notification::try_from(row)?;
            let Some(reference_id) = notification.reference_id.clone() else {
                continue;
            };
            match result.entry(reference_id) {
                Entry::Vacant(entry) => {
                    entry.insert(notification);
                }
                Entry::Occupied(mut entry) => {
                    if notification.datetime > entry.get().datetime {
                        entry.insert(notification);
                    }
                }
            }
        }
        Ok(result)
    }

    async fn get_latest_by_reference(
        &self,
        reference: &str,
        notification_type: NotificationType,
    ) -> Result<Option<Notification>> {
        let result = self
            .list(NotificationFilter {
                active: Some(true),
                reference_id: Some(reference.to_owned()),
                notification_type: Some(notification_type.to_string()),
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        Ok(result.first().cloned())
    }

    async fn get_latest_by_reference_and_node_id(
        &self,
        reference: &str,
        notification_type: NotificationType,
        node_id: &NodeId,
    ) -> Result<Option<Notification>> {
        let result = self
            .list(NotificationFilter {
                active: Some(true),
                reference_id: Some(reference.to_owned()),
                notification_type: Some(notification_type.to_string()),
                node_ids: vec![node_id.clone()],
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        Ok(result.first().cloned())
    }

    async fn list_by_type(&self, notification_type: NotificationType) -> Result<Vec<Notification>> {
        self.list(NotificationFilter {
            active: Some(true),
            notification_type: Some(notification_type.to_string()),
            ..Default::default()
        })
        .await
    }

    async fn mark_as_done(&self, notification_id: &str) -> Result<()> {
        sqlx::query(MARK_NOTIFICATION_DONE)
            .bind(notification_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete(&self, notification_id: &str) -> Result<()> {
        sqlx::query(DELETE_NOTIFICATION)
            .bind(notification_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<()> {
        sqlx::query(INSERT_SENT_NOTIFICATION)
            .bind(notification_type_to_db(&NotificationType::Bill))
            .bind(bill_id.to_string())
            .bind(block_height)
            .bind(action_type_to_db(&action_type))
            .bind(timestamp_to_db(Timestamp::now())?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(SELECT_SENT_NOTIFICATION_EXISTS)
            .bind(notification_type_to_db(&NotificationType::Bill))
            .bind(bill_id.to_string())
            .bind(block_height)
            .bind(action_type_to_db(&action_type))
            .fetch_one(&self.pool)
            .await?;
        Ok(exists)
    }

    async fn notification_exists_for_event_id(
        &self,
        event_id: &str,
        node_id: &NodeId,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(SELECT_NOTIFICATION_EVENT_EXISTS)
            .bind(event_id)
            .bind(node_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresNotificationStore;
    use crate::tests::notification;
    use sqlx::PgPool;

    macro_rules! contract_test {
        ($name:ident, $contract:ident) => {
            #[sqlx::test(migrations = "migrations/postgres")]
            async fn $name(pool: PgPool) {
                let store = PostgresNotificationStore::new(pool);
                notification::$contract(&store).await;
            }
        };
    }

    contract_test!(
        notification_sent_returns_false_for_non_existing,
        test_notification_sent_returns_false_for_non_existing
    );

    contract_test!(
        notification_sent_returns_true_for_existing,
        test_notification_sent_returns_true_for_existing
    );

    contract_test!(
        notification_sent_returns_false_for_different_action,
        test_notification_sent_returns_false_for_different_action
    );

    contract_test!(
        inserts_and_queries_notification,
        test_inserts_and_queries_notification
    );

    contract_test!(
        deletes_existing_notification,
        test_deletes_existing_notification
    );

    contract_test!(
        marks_done_and_no_longer_returns_in_list,
        test_marks_done_and_no_longer_returns_in_list
    );

    contract_test!(
        marks_done_and_no_longer_returns_by_references,
        test_marks_done_and_no_longer_returns_by_references
    );

    contract_test!(
        latest_by_reference_really_returns_latest,
        test_latest_by_reference_really_returns_latest
    );

    contract_test!(
        latest_by_reference_and_node_id,
        test_latest_by_reference_and_node_id
    );

    contract_test!(returns_all_active_by_type, test_returns_all_active_by_type);

    contract_test!(
        returns_active_status_for_node_ids,
        test_returns_active_status_for_node_ids
    );

    contract_test!(
        notification_exists_for_event_id,
        test_notification_exists_for_event_id
    );
}
