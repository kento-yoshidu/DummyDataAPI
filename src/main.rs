use std::env;
use std::fs;
use std::sync::Mutex;
use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use serde::{Serialize, Deserialize};
use env_logger::Env;
use log::error;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString, PasswordHash};
use std::io::Read;

mod book;
use book::{
    Book,
    get_book_by_id,
    get_books,
    get_book_with_query,
    add_or_update_book,
};

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2.hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    password: String,
}

struct AppState {
    data_file: String,
}

fn load_users() -> Vec<User> {
    let mut file = match fs::File::open("src/users/users.json") {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    serde_json::from_str(&contents).unwrap_or_else(|_| Vec::new())
}

fn save_user(username: &str, password: &str) -> Result<(), String> {
    let hashed_password = hash_password(password);
    let mut users = load_users();

    // ユーザー名が既に存在するかチェック
    if users.iter().any(|user| user.username == username) {
        return Err(format!("Username '{}' is already taken.", username));
    }

    let new_user = User {
        username: username.to_string(),
        password: hashed_password,
    };

    users.push(new_user);

    let json = serde_json::to_string_pretty(&users).unwrap();
    fs::write("src/users/users.json", json).expect("Failed to write file");

    Ok(())
}

fn verify_password(stored_hash: &str, password: &str) -> bool {
    let parsed_hash = PasswordHash::new(stored_hash).unwrap();
    let argon2 = Argon2::default();

    argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let current_dir = env::current_dir().expect("Failed to get current dir");
    let file_path = current_dir.join("src/data/book.json").to_str().unwrap().to_string();

    let books = web::Data::new(Mutex::new(AppState {
        data_file: file_path,
    }));

    let result = save_user("user2", "password");

    println!("{:?}", result);

    HttpServer::new(move || {
        App::new()
            .app_data(books.clone())
            .wrap(
                Cors::default()
                    .allowed_origin_fn(|origin, _req_head| {
                        let allowed_origins = vec![
                            "http://localhost:3000",
                            "http://localhost:5173",
                        ];

                        let allowed = allowed_origins
                            .into_iter()
                            .any(|allowed_origin| allowed_origin == origin.to_str().unwrap());

                        if !allowed {
                            error!("CORS violation: Origin {:?} is not allowed", origin);
                        }

                        allowed
                    })
                    .allow_any_method()
                    .allow_any_header()
            )
            .wrap(Logger::default())
            .service(get_books)
            .service(get_book_by_id)
            .service(get_book_with_query)
            .service(add_or_update_book)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use actix_web::http::StatusCode;

    fn setup_books() -> web::Data<Mutex<AppState>> {
        let current_dir = env::current_dir().expect("Failed to get current dir");
        let file_path = current_dir.join("src/data/book.json").to_str().unwrap().to_string();

        web::Data::new(Mutex::new(AppState {
            data_file: file_path,
        }))
    }

    #[actix_rt::test]
    async fn test_get_books() {
        let books = setup_books();

        let app = test::init_service(App::new().app_data(books).service(get_books)).await;

        let req = test::TestRequest::get().uri("/books").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);

        assert!(body.contains("Rust Basics"));
        assert!(body.contains("Async in Rust"));
        assert!(body.contains("Parallelism"));
    }

    #[actix_rt::test]
    async fn test_get_book_by_id() {
        let books = setup_books();

        let app = test::init_service(App::new().app_data(books).service(get_book_by_id)).await;

        let req = test::TestRequest::get().uri("/books/id/1").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);

        assert!(body.contains("Rust Basics"));

        let req = test::TestRequest::get().uri("/books/id/50").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);

        assert!(body.contains("Parallelism"));
    }

    #[actix_rt::test]
    async fn test_get_book_not_found() {
        let books = setup_books();

        let app = test::init_service(App::new().app_data(books).service(get_book_by_id)).await;

        let req = test::TestRequest::get().uri("/books/id/999").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<Book> = test::read_body_json(resp).await;

        assert!(body.is_empty());
    }

    #[actix_rt::test]
    async fn test_get_book_with_query() {
        let books = setup_books();

        let app = test::init_service(App::new().app_data(books).service(get_book_with_query)).await;

        let req = test::TestRequest::get().uri("/books/search?id=1").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);

        assert!(body.contains("Rust Basics"));
    }

    // ユーザー関係
    #[actix_rt::test]
    async  fn test_password_hashing_and_verification() {
        let password = "password";
        let hashed_password = hash_password(&password);

        assert!(verify_password(&hashed_password, password));
        assert!(!verify_password(&hashed_password, "wrong_password"));
    }
}
