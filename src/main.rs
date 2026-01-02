use std::env;
use actix_web::{
    get,
    web,
    App,
    HttpServer,
    HttpResponse,
    HttpRequest,
    Responder,
    Error,
    error::ErrorUnauthorized,
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use dotenvy::dotenv;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use tokio::sync::OnceCell;
use jsonwebtoken::Algorithm;

struct AppState {
    db: sqlx::PgPool,
    cognito: CognitoConfig,
}

#[derive(Clone)]
#[allow(dead_code)]
struct CognitoConfig {
    client_id: String,
    region: String,
    user_pool_id: String,
    issuer: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn extract_id_token(req: &HttpRequest) -> Result<String, Error> {
    req.cookie("id_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| ErrorUnauthorized("id_token not found"))
}

#[get("/health")]
async fn health(data: web::Data<AppState>) -> impl Responder {
    let result = sqlx::query("select 1")
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("DB OK"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

fn load_cognito_config() -> CognitoConfig {
    let client_id =
        env::var("COGNITO_CLIENT_ID").expect("COGNITO_CLIENT_ID must be set");

    let region =
        env::var("COGNITO_REGION").expect("COGNITO_REGION must be set");

    let user_pool_id =
        env::var("COGNITO_USER_POOL_ID").expect("COGNITO_USER_POOL_ID must be set");

    let issuer = format!(
        "https://cognito-idp.{}.amazonaws.com/{}",
        region,
        user_pool_id
    );

    CognitoConfig {
        client_id,
        region,
        user_pool_id,
        issuer,
    }
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CognitoClaims {
    sub: String,
    email: String,
    exp: usize,
}

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello World")
}

#[get("/user")]
async fn get_user(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {

    let token = extract_id_token(&req)?;

    let jwks = get_jwks(&data.cognito).await?;
    let claims = validate_token(&token, jwks, &data.cognito)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| actix_web::error::ErrorUnauthorized("invalid sub"))?;

    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, email, name, role, created_at, updated_at
        FROM users
        WHERE id = $1
        "#
    )
    .bind(user_id)
    .fetch_optional(&data.db)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;

    match user {
        Some(user) => Ok(HttpResponse::Ok().json(user)),
        None => Err(actix_web::error::ErrorUnauthorized("user not registered")),
    }
}

static JWKS: OnceCell<Jwks> = OnceCell::const_new();

async fn get_jwks(cognito: &CognitoConfig) -> Result<&'static Jwks, actix_web::Error> {
    // let cognito_region = env::var("COGNITO_REGION").expect("COGNITO_REGION must be set");
    // let cognito_user_pool_id = env::var("COGNITO_USER_POOL_ID").expect("COGNITO_USER_POOL_ID must be set");
    JWKS.get_or_try_init(|| async {
        let url = format!("https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json", cognito.region, cognito.user_pool_id);

        let jwks = reqwest::get(url)
            .await
            .map_err(|_| actix_web::error::ErrorInternalServerError("jwks fetch failed"))?
            .json::<Jwks>()
            .await
            .map_err(|_| actix_web::error::ErrorInternalServerError("jwks parse failed"))?;

        Ok(jwks)
    })
    .await
}

fn validate_token(
    token: &str,
    jwks: &Jwks,
    cognito: &CognitoConfig,
) -> Result<CognitoClaims, actix_web::Error> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| actix_web::error::ErrorUnauthorized("invalid header"))?;

    let kid = header.kid.ok_or_else(|| {
        actix_web::error::ErrorUnauthorized("kid not found")
    })?;

    let jwk = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("jwk not found"))?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|_| actix_web::error::ErrorUnauthorized("invalid key"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[cognito.client_id.as_str()]);
    validation.set_issuer(&[cognito.issuer.as_str()]);

    decode::<CognitoClaims>(token, &decoding_key, &validation)
        .map(|d| d.claims)
        .map_err(|_| actix_web::error::ErrorUnauthorized("invalid token"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let cognito = load_cognito_config();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = web::Data::new(AppState {
        db: pool,
        cognito,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(hello)
            .service(get_user)
            .service(health)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
