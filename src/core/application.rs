use crate::core::config::Config;
use crate::domain::auth::AuthService;
use crate::domain::lichen::LichenService;
use std::sync::Arc;

pub trait ApplicationServices: Clone + Send + Sync {
    type AUTH: AuthService + Send;
    type LICHEN: LichenService + Send;

    fn config(&self) -> Config;

    fn auth_service(&self) -> Arc<Self::AUTH>;

    fn lichen_service(&self) -> Arc<Self::LICHEN>;
}

pub struct Application<AUTH, LICHEN>
where
    AUTH: AuthService + Send + Sync + 'static,
    LICHEN: LichenService + Send + Sync + 'static,
{
    config: Config,
    auth_service: Arc<AUTH>,
    lichen_service: Arc<LICHEN>,
}

impl<AUTH, LICHEN> Application<AUTH, LICHEN>
where
    AUTH: AuthService + Send + Sync + 'static,
    LICHEN: LichenService + Send + Sync + 'static,
{
    pub fn new(config: Config, auth_service: AUTH, lichen_service: LICHEN) -> Self {
        Self {
            config,
            auth_service: Arc::new(auth_service),
            lichen_service: Arc::new(lichen_service),
        }
    }
}

impl<AUTH, LICHEN> Clone for Application<AUTH, LICHEN>
where
    AUTH: AuthService + Send + Sync + 'static,
    LICHEN: LichenService + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            auth_service: self.auth_service.clone(),
            lichen_service: self.lichen_service.clone(),
        }
    }
}

impl<AUTH, LICHEN> ApplicationServices for Application<AUTH, LICHEN>
where
    AUTH: AuthService + Send + Sync + 'static,
    LICHEN: LichenService + Send + Sync + 'static,
{
    type AUTH = AUTH;
    type LICHEN = LICHEN;

    fn config(&self) -> Config {
        self.config.clone()
    }

    fn auth_service(&self) -> Arc<Self::AUTH> {
        self.auth_service.clone()
    }

    fn lichen_service(&self) -> Arc<Self::LICHEN> {
        self.lichen_service.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::core::application::Application;
    use crate::core::config::Config;
    use crate::domain::auth::{AuthService, MockAuthService};
    use crate::domain::lichen::{LichenService, MockLichenService};

    pub struct MockAppInstanceParameters<AUTH, LICHEN>
    where
        AUTH: AuthService + Send + Sync + 'static,
        LICHEN: LichenService + Send + Sync + 'static,
    {
        pub config: Option<Config>,
        pub auth_service: Option<AUTH>,
        pub lichen_service: Option<LICHEN>,
    }

    impl<AUTH, LICHEN> Application<AUTH, LICHEN>
    where
        AUTH: AuthService + Send + Sync + 'static,
        LICHEN: LichenService + Send + Sync + 'static,
    {
        pub fn mock_instance(
            params: MockAppInstanceParameters<MockAuthService, MockLichenService>,
        ) -> Application<MockAuthService, MockLichenService> {
            let app_config = params.config.unwrap_or_default();
            let auth_service = params.auth_service.unwrap_or(MockAuthService::new());
            let lichen_service = params.lichen_service.unwrap_or(MockLichenService::new());

            let app = Application::new(app_config, auth_service, lichen_service);

            app
        }
    }
}
