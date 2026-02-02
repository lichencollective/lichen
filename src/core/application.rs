use crate::core::config::Config;
use crate::domain::auth::AuthService;
use std::sync::Arc;

pub trait ApplicationServices: Clone + Send + Sync {
    type AUTH: AuthService + Send;

    fn config(&self) -> Config;

    fn auth_service(&self) -> Arc<Self::AUTH>;
}

pub struct Application<AUTH>
where
    AUTH: AuthService + Send + Sync + 'static,
{
    config: Config,
    auth_service: Arc<AUTH>,
}

impl<AUTH> Application<AUTH>
where
    AUTH: AuthService + Send + Sync + 'static,
{
    pub fn new(config: Config, auth_service: AUTH) -> Self {
        Self {
            config,
            auth_service: Arc::new(auth_service),
        }
    }
}

impl<AUTH> Clone for Application<AUTH>
where
    AUTH: 'static + AuthService + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            auth_service: self.auth_service.clone(),
        }
    }
}

impl<AUTH> ApplicationServices for Application<AUTH>
where
    AUTH: AuthService + Send + Sync + 'static,
{
    type AUTH = AUTH;

    fn config(&self) -> Config {
        self.config.clone()
    }

    fn auth_service(&self) -> Arc<Self::AUTH> {
        self.auth_service.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::core::application::Application;
    use crate::core::config::Config;
    use crate::domain::auth::{AuthService, MockAuthService};

    pub struct MockAppInstanceParameters<AUTH>
    where
        AUTH: AuthService + Send + Sync + 'static,
    {
        pub config: Option<Config>,
        pub auth_service: Option<AUTH>,
    }

    impl<AUTH> Application<AUTH>
    where
        AUTH: AuthService + Send + Sync + 'static,
    {
        pub fn mock_instance(
            params: MockAppInstanceParameters<MockAuthService>,
        ) -> Application<MockAuthService> {
            let app_config = params.config.unwrap_or_default();
            let auth_service = params.auth_service.unwrap_or(MockAuthService::new());

            let app = Application::new(app_config, auth_service);

            app
        }
    }
}
