use std::fs;
use std::sync::Mutex;
use actix_web::{get, post, web, HttpResponse, Responder};
use serde::{Serialize, Deserialize};
use thiserror::Error;

struct AppState {
    data_file: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Book {
    id: u32,
    title: String,
    content: String,
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct BookQuery {
    id: Option<u32>,
    tag: Option<String>,
}

#[derive(Debug, Error)]
enum BookError {
    #[error("Failed to read JSON file")]
    FileReadError(#[from] std::io::Error),

    #[error("Failed to parse JSON")]
    JsonParseError(#[from] serde_json::Error),
}

impl actix_web::ResponseError for BookError {
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        match self {
            BookError::FileReadError(_) => HttpResponse::InternalServerError().body("Failed to read JSON"),
            BookError::JsonParseError(_) => HttpResponse::InternalServerError().body("Failed to parse JSON"),
        }
    }
}

fn read_books_from_file(file_path: &str) -> Result<Vec<Book>, BookError> {
    let contents = fs::read_to_string(file_path)?;

    let books: Vec<Book> = serde_json::from_str(&contents)?;

    Ok(books)
}

#[get("/books")]
async fn get_books(data: web::Data<Mutex<AppState>>) -> Result<impl Responder, BookError> {
    let file_path = {
        let state = data.lock().unwrap();
        state.data_file.clone()
    };

    let books = read_books_from_file(&file_path)?;
    Ok(HttpResponse::Ok().json(books))
}

fn write_books_to_file(file_path: &str, books: &Vec<Book>) -> Result<(), BookError> {
    let contents = serde_json::to_string_pretty(books)?;

    fs::write(file_path, contents)?;

    Ok(())
}

#[post("/books")]
async fn add_or_update_book(data: web::Data<Mutex<AppState>>, new_book: web::Json<Book>) -> Result<impl Responder, BookError> {
    let file_path = {
        let state = data.lock().unwrap();
        state.data_file.clone()
    };

    let mut books = read_books_from_file(&file_path)?;

    let existing_book_pos = books.iter_mut().position(|b| b.id == new_book.id);

    match existing_book_pos {
        Some(pos) => {
            books[pos] = new_book.into_inner();
        }
        None => {
            books.push(new_book.into_inner());
        }
    }

    // ファイルに保存
    write_books_to_file(&file_path, &books)?;

    Ok(HttpResponse::Ok().json(books))
}

#[get("/books/search")]
async fn get_book_with_query(
    data: web::Data<Mutex<AppState>>,
    query: web::Query<BookQuery>,
) -> Result<impl Responder, BookError> {
    let file_path = {
        let state = data.lock().unwrap();
        state.data_file.clone()
    };

    let books = read_books_from_file(&file_path)?;

    let filtered_books: Vec<Book> = books.into_iter()
        .filter(|b| {
            (query.id.map_or(true, |id| b.id == id as u32)) &&
            (query.tag.as_deref().map_or(true, |tag| b.tags.contains(&tag.to_string())))
        })
        .collect();

    Ok(HttpResponse::Ok().json(filtered_books))
}

#[get("/books/id/{id}")]
async fn get_book_by_id(data: web::Data::<Mutex<AppState>>, id: web::Path<u32>) -> Result<impl Responder, BookError> {
    let file_path = {
        let state = data.lock().unwrap();
        state.data_file.clone()
    };
    let id = id.into_inner();

    let books = read_books_from_file(&file_path)?;

    let filtered_book: Vec<Book> = books.into_iter()
        .filter(|b| b.id == id)
        .collect();

    Ok(HttpResponse::Ok().json(filtered_book))
}