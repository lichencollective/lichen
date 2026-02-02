use crate::domain::auth::{
    AuthService, OIDCCallbackParams, OIDCLoginParams, OIDCPort, OIDCRefreshParams,
    ServiceAuthenticatedError, ServiceAuthenticatedParams, ServiceCallbackError,
    ServiceCallbackParams, ServiceCallbackResult, ServiceLoginError, ServiceLoginParams,
    ServiceLoginResult, ServiceLogoutError, ServiceLogoutParams, ServiceProfileError,
    ServiceProfileParams, ServiceProfileResult,
};
use crate::domain::session::{SessionLoginCallback, SessionPort, UserSession};
use crate::outbound::session::SessionFactory;
use async_trait::async_trait;
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Service<SESSION, OIDC, F>
where
    SESSION: SessionPort + Send + Sync + 'static,
    OIDC: OIDCPort + Send + Sync + 'static,
    F: SessionFactory<SESSION> + Send + Sync + 'static,
{
    oidc_adapter: Arc<OIDC>,
    session_factory: F,
    _session: PhantomData<SESSION>,
}

impl<SESSION, OIDC, F> Service<SESSION, OIDC, F>
where
    SESSION: SessionPort + Send + Sync + 'static,
    OIDC: OIDCPort + Send + Sync + 'static,
    F: SessionFactory<SESSION> + Send + Sync + 'static,
{
    pub fn new(oidc_adapter: OIDC, session_adapter_factory: F) -> Self {
        Self {
            oidc_adapter: Arc::new(oidc_adapter),
            session_factory: session_adapter_factory,
            _session: PhantomData,
        }
    }
}

#[async_trait]
impl<SESSION, OIDC, F> AuthService for Service<SESSION, OIDC, F>
where
    SESSION: SessionPort + Send + Sync + 'static,
    OIDC: OIDCPort + Send + Sync + 'static,
    F: SessionFactory<SESSION> + Send + Sync + 'static,
{
    async fn login(
        &self,
        params: ServiceLoginParams,
    ) -> Result<ServiceLoginResult, ServiceLoginError> {
        let session = self.session_factory.build(params.session);
        let login = self.oidc_adapter.login(OIDCLoginParams {}).await;

        tracing::debug!("writing session");
        let _ = session
            .write_oidc_callback(SessionLoginCallback {
                app_uri: params.app_uri,
                nonce: login.nonce.clone(),
                csrf_token: login.csrf_token.clone(),
                pkce_verifier: login.pkce_verifier.clone(),
            })
            .await?;
        tracing::debug!("wrote session");

        Ok(ServiceLoginResult {
            authorization_uri: login.authorization_url,
        })
    }

    async fn callback(
        &self,
        params: ServiceCallbackParams,
    ) -> Result<ServiceCallbackResult, ServiceCallbackError> {
        let session = self.session_factory.build(params.session);
        let login_callback_session = session
            .get_oidc_callback()
            .await?
            .ok_or(ServiceCallbackError::InvalidSession)?;

        if params.state != login_callback_session.csrf_token {
            return Err(ServiceCallbackError::InvalidSession);
        }

        let callback_result = self
            .oidc_adapter
            .callback(OIDCCallbackParams {
                code: params.code,
                pkce_code_verifier: login_callback_session.pkce_verifier,
                nonce: login_callback_session.nonce,
            })
            .await?;

        // prevent replay and clear the user session before we add a new one
        session.flush().await?;

        session
            .write_user_session(UserSession {
                session_tokens: callback_result.session_tokens,
                user_id: callback_result.subject,
                groups: callback_result.groups,
                username: callback_result.username,
            })
            .await?;

        Ok(ServiceCallbackResult {
            redirect_uri: login_callback_session.app_uri,
        })
    }

    async fn logout(&self, params: ServiceLogoutParams) -> Result<(), ServiceLogoutError> {
        let session = self.session_factory.build(params.session);
        session.flush().await?;

        Ok(())
    }

    async fn authenticated(
        &self,
        params: ServiceAuthenticatedParams,
    ) -> Result<bool, ServiceAuthenticatedError> {
        let session = self.session_factory.build(params.session);

        if let Some(user_session) = session.get_user_session().await? {
            if user_session.session_tokens.refresh_token_expired() {
                session.flush().await?;

                return Ok(false);
            }

            if user_session.session_tokens.access_token_expired() {
                let refresh_result = self
                    .oidc_adapter
                    .refresh(OIDCRefreshParams {
                        subject: user_session.user_id.clone(),
                        refresh_token: user_session.session_tokens.refresh_token.clone(),
                    })
                    .await?;

                session
                    .write_user_session(UserSession {
                        session_tokens: refresh_result.session_tokens,
                        user_id: user_session.user_id,
                        groups: user_session.groups,
                        username: user_session.username,
                    })
                    .await?;
            }
        } else {
            return Ok(false);
        }

        Ok(true)
    }

    async fn profile(
        &self,
        params: ServiceProfileParams,
    ) -> Result<ServiceProfileResult, ServiceProfileError> {
        let session = self.session_factory.build(params.session);

        if let Some(user_session) = session.get_user_session().await? {
            return Ok(ServiceProfileResult {
                user_id: user_session.user_id,
                groups: user_session.groups,
                username: user_session.username,
            });
        }

        Err(ServiceProfileError::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::auth::OIDCRefreshError::RefreshTokenError;
    use crate::domain::auth::{
        MockOIDCPort, OIDCCallbackError, OIDCCallbackResult, OIDCLoginResult, OIDCRefreshResult,
        SessionTokens,
    };
    use crate::domain::session::MockSessionPort;
    use crate::domain::session::SessionError::WriteSessionError;
    use crate::outbound::session::MockSessionFactory;
    use std::future;
    use std::time::{Duration, SystemTime};
    use tower_sessions::{MemoryStore, Session};

    fn unexpired_tokens() -> SessionTokens {
        SessionTokens {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            id_token: "".to_string(),
            access_token_expires_at: SystemTime::now() + Duration::from_mins(5),
            refresh_token_expires_at: SystemTime::now() + Duration::from_mins(5),
        }
    }

    fn user_session_unexpired() -> UserSession {
        UserSession {
            session_tokens: unexpired_tokens(),
            user_id: "foobar".to_string(),
            groups: vec![],
            username: None,
        }
    }

    fn user_session_expired_access_token() -> UserSession {
        UserSession {
            session_tokens: SessionTokens {
                access_token: "".to_string(),
                refresh_token: "".to_string(),
                id_token: "".to_string(),
                access_token_expires_at: SystemTime::UNIX_EPOCH,
                refresh_token_expires_at: SystemTime::now() + Duration::from_mins(5),
            },
            user_id: "foobar".to_string(),
            groups: vec![],
            username: None,
        }
    }

    fn user_session_expired_refresh_token() -> UserSession {
        UserSession {
            session_tokens: SessionTokens {
                access_token: "".to_string(),
                refresh_token: "".to_string(),
                id_token: "".to_string(),
                access_token_expires_at: SystemTime::UNIX_EPOCH,
                refresh_token_expires_at: SystemTime::UNIX_EPOCH,
            },
            user_id: "foobar".to_string(),
            groups: vec![],
            username: None,
        }
    }

    fn memory_session() -> Session {
        let store = Arc::new(MemoryStore::default());
        Session::new(None, store, None)
    }

    #[tokio::test]
    async fn test_profile() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(Some(user_session_unexpired())))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .profile(ServiceProfileParams {
                session: memory_session(),
            })
            .await
            .unwrap();

        assert_eq!("foobar", result.user_id);
    }

    #[tokio::test]
    async fn test_profile_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Err(WriteSessionError))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .profile(ServiceProfileParams {
                session: memory_session(),
            })
            .await;

        assert_eq!(true, result.is_err())
    }

    #[tokio::test]
    async fn test_authenticated() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(Some(user_session_unexpired())))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .authenticated(ServiceAuthenticatedParams {
                session: memory_session(),
            })
            .await
            .unwrap();

        assert_eq!(true, result);
    }

    #[tokio::test]
    async fn test_authenticated_expired_refresh() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session.expect_get_user_session().times(1).return_once(|| {
            Box::pin(future::ready(Ok(
                Some(user_session_expired_refresh_token()),
            )))
        });
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(()))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .authenticated(ServiceAuthenticatedParams {
                session: memory_session(),
            })
            .await
            .unwrap();

        assert_eq!(false, result);
    }

    #[tokio::test]
    async fn test_authenticated_expired_access() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_refresh().times(1).return_once(|_| {
            Box::pin(future::ready(Ok(OIDCRefreshResult {
                session_tokens: unexpired_tokens(),
            })))
        });
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(Some(user_session_expired_access_token())))));
        session
            .expect_write_user_session()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Ok(()))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .authenticated(ServiceAuthenticatedParams {
                session: memory_session(),
            })
            .await
            .unwrap();

        assert_eq!(true, result);
    }

    #[tokio::test]
    async fn test_authenticated_expired_access_refresh_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter
            .expect_refresh()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Err(RefreshTokenError))));
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(Some(user_session_expired_access_token())))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .authenticated(ServiceAuthenticatedParams {
                session: memory_session(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_authenticated_expired_access_write_session_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_refresh().times(1).return_once(|_| {
            Box::pin(future::ready(Ok(OIDCRefreshResult {
                session_tokens: unexpired_tokens(),
            })))
        });
        let mut session = MockSessionPort::new();
        session
            .expect_get_user_session()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(Some(user_session_expired_access_token())))));
        session
            .expect_write_user_session()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Err(WriteSessionError))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .authenticated(ServiceAuthenticatedParams {
                session: memory_session(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_logout() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(()))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .logout(ServiceLogoutParams {
                session: memory_session(),
                app_uri: "".to_string(),
            })
            .await;

        assert_eq!(false, result.is_err());
    }

    #[tokio::test]
    async fn test_logout_flush_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Err(WriteSessionError))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .logout(ServiceLogoutParams {
                session: memory_session(),
                app_uri: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_callback().times(1).return_once(|_| {
            Box::pin(future::ready(Ok(OIDCCallbackResult {
                session_tokens: unexpired_tokens(),
                subject: "".to_string(),
                groups: vec![],
                username: None,
            })))
        });
        let mut session = MockSessionPort::new();
        session.expect_get_oidc_callback().times(1).return_once(|| {
            Box::pin(future::ready(Ok(Some(SessionLoginCallback {
                app_uri: "".to_string(),
                nonce: "".to_string(),
                csrf_token: "csrf_token".to_string(),
                pkce_verifier: "".to_string(),
            }))))
        });
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(()))));
        session
            .expect_write_user_session()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Ok(()))));

        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(false, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_session_get_callback_none() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_get_oidc_callback()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(None))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_session_get_callback_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session
            .expect_get_oidc_callback()
            .times(1)
            .return_once(|| Box::pin(future::ready(Err(WriteSessionError))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_invalid_csrf() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let oidc_adapter = MockOIDCPort::new();
        let mut session = MockSessionPort::new();
        session.expect_get_oidc_callback().times(1).return_once(|| {
            Box::pin(future::ready(Ok(Some(SessionLoginCallback {
                app_uri: "".to_string(),
                nonce: "".to_string(),
                csrf_token: "incorrect csrf_token".to_string(),
                pkce_verifier: "".to_string(),
            }))))
        });
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_callback_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter
            .expect_callback()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Err(OIDCCallbackError::UserInfoError))));
        let mut session = MockSessionPort::new();
        session.expect_get_oidc_callback().times(1).return_once(|| {
            Box::pin(future::ready(Ok(Some(SessionLoginCallback {
                app_uri: "".to_string(),
                nonce: "".to_string(),
                csrf_token: "csrf_token".to_string(),
                pkce_verifier: "".to_string(),
            }))))
        });
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_flush_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_callback().times(1).return_once(|_| {
            Box::pin(future::ready(Ok(OIDCCallbackResult {
                session_tokens: unexpired_tokens(),
                subject: "".to_string(),
                groups: vec![],
                username: None,
            })))
        });
        let mut session = MockSessionPort::new();
        session.expect_get_oidc_callback().times(1).return_once(|| {
            Box::pin(future::ready(Ok(Some(SessionLoginCallback {
                app_uri: "".to_string(),
                nonce: "".to_string(),
                csrf_token: "csrf_token".to_string(),
                pkce_verifier: "".to_string(),
            }))))
        });
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Err(WriteSessionError))));

        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_callback_write_user_session_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_callback().times(1).return_once(|_| {
            Box::pin(future::ready(Ok(OIDCCallbackResult {
                session_tokens: unexpired_tokens(),
                subject: "".to_string(),
                groups: vec![],
                username: None,
            })))
        });
        let mut session = MockSessionPort::new();
        session.expect_get_oidc_callback().times(1).return_once(|| {
            Box::pin(future::ready(Ok(Some(SessionLoginCallback {
                app_uri: "".to_string(),
                nonce: "".to_string(),
                csrf_token: "csrf_token".to_string(),
                pkce_verifier: "".to_string(),
            }))))
        });
        session
            .expect_flush()
            .times(1)
            .return_once(|| Box::pin(future::ready(Ok(()))));
        session
            .expect_write_user_session()
            .times(1)
            .return_once(|_| Box::pin(future::ready(Err(WriteSessionError))));

        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .callback(ServiceCallbackParams {
                session: memory_session(),
                state: "csrf_token".to_string(),
                code: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }

    #[tokio::test]
    async fn test_login() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_login().once().return_once(|_| {
            Box::pin(future::ready(OIDCLoginResult {
                authorization_url: "".to_string(),
                csrf_token: "".to_string(),
                nonce: "".to_string(),
                pkce_verifier: "".to_string(),
            }))
        });
        let mut session = MockSessionPort::new();
        session
            .expect_write_oidc_callback()
            .once()
            .return_once(|_| Box::pin(future::ready(Ok(()))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .login(ServiceLoginParams {
                session: memory_session(),
                app_uri: "".to_string(),
            })
            .await;

        assert_eq!(false, result.is_err());
    }

    #[tokio::test]
    async fn test_login_write_callback_error() {
        let mut session_factory: MockSessionFactory<MockSessionPort> = MockSessionFactory::new();
        let mut oidc_adapter = MockOIDCPort::new();
        oidc_adapter.expect_login().once().return_once(|_| {
            Box::pin(future::ready(OIDCLoginResult {
                authorization_url: "".to_string(),
                csrf_token: "".to_string(),
                nonce: "".to_string(),
                pkce_verifier: "".to_string(),
            }))
        });
        let mut session = MockSessionPort::new();
        session
            .expect_write_oidc_callback()
            .once()
            .return_once(|_| Box::pin(future::ready(Err(WriteSessionError))));
        session_factory
            .expect_build()
            .times(1)
            .return_once(|_| session);

        let service: Service<MockSessionPort, MockOIDCPort, MockSessionFactory<MockSessionPort>> =
            Service::new(oidc_adapter, session_factory);
        let result = service
            .login(ServiceLoginParams {
                session: memory_session(),
                app_uri: "".to_string(),
            })
            .await;

        assert_eq!(true, result.is_err());
    }
}
