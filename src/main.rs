use actix_web::{App, HttpServer, web};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use dotenvy::dotenv;
use std::env;
use actix_web::{get, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use uuid::Uuid;

struct AppState {
    db: sqlx::PgPool,
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

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello World")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // let database_url = env::var("DATABASE_URL")
    //     .expect("DATABASE_URL must be set");

    // let pool = PgPoolOptions::new()
    //     .max_connections(5)
    //     .connect(&database_url)
    //     .await
    //     .expect("Failed to connect to database");

    // let state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        App::new()
            // .app_data(state.clone())
            .service(hello)
            .service(health)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
