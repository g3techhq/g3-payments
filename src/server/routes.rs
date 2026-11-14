//! Webhook routes, for an app to mount under `/api/v1`:
//!
//! - `POST /stripe_webhooks` (feature `stripe`)
//! - `POST /app_store_notifications` (feature `app-store`)
//!
//! The paths are the ones Swift Circuits and Greenside Partee already give
//! Stripe and App Store Connect, so mounting these changes nothing there.
//! Each answers 200 once handled (or when there is nothing to do), 400 for a
//! delivery that does not verify, and 500 when it should be sent again.
//!
//! ```ignore
//! let service = Arc::new(PaymentsService::new(catalog, store).with_stripe(stripe));
//! let app = app.nest("/api/v1", g3_payments::server::routes::routes(service));
//! ```

use std::sync::Arc;

use axum::{Router, http::StatusCode};

use super::{
    service::{PaymentsService, WebhookFailure, WebhookOutcome},
    store::Store,
};

/// The webhook routes for `service`'s providers.
pub fn routes<S: Store + 'static>(service: Arc<PaymentsService<S>>) -> Router {
    let router = Router::new();
    #[cfg(feature = "stripe")]
    let router = router.route(
        "/stripe_webhooks",
        axum::routing::post(stripe::handle::<S>).with_state(service.clone()),
    );
    #[cfg(feature = "app-store")]
    let router = router.route(
        "/app_store_notifications",
        axum::routing::post(app_store::handle::<S>).with_state(service.clone()),
    );
    let _ = service;
    router
}

#[cfg_attr(
    not(any(feature = "stripe", feature = "app-store")),
    allow(dead_code, reason = "Used by the webhook routes.")
)]
fn status(result: Result<WebhookOutcome, WebhookFailure>) -> StatusCode {
    match result {
        Ok(_) => StatusCode::OK,
        Err(WebhookFailure::Rejected) => StatusCode::BAD_REQUEST,
        Err(WebhookFailure::Retry(_)) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(feature = "stripe")]
mod stripe {
    use super::*;
    use axum::{body::Bytes, extract::State, http::HeaderMap};

    pub(super) async fn handle<S: Store + 'static>(
        State(service): State<Arc<PaymentsService<S>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        let Some(signature) = headers
            .get("stripe-signature")
            .and_then(|value| value.to_str().ok())
        else {
            return StatusCode::BAD_REQUEST;
        };
        status(service.handle_stripe_webhook(&body, signature).await)
    }
}

#[cfg(feature = "app-store")]
mod app_store {
    use super::*;
    use axum::{body::Bytes, extract::State};

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Notification {
        signed_payload: String,
    }

    pub(super) async fn handle<S: Store + 'static>(
        State(service): State<Arc<PaymentsService<S>>>,
        body: Bytes,
    ) -> StatusCode {
        let Ok(notification) = serde_json::from_slice::<Notification>(&body) else {
            return StatusCode::BAD_REQUEST;
        };
        status(
            service
                .handle_app_store_notification(&notification.signed_payload)
                .await,
        )
    }
}
