-- Pertama, buat tabel "categories".
CREATE TABLE categories (
    id serial PRIMARY KEY,
    name VARCHAR(50) NOT NULL
);

-- Kemudian, buat tabel "books".
CREATE TABLE books (
    id serial PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    publication_year INTEGER,
    category_id INTEGER REFERENCES categories(id),
    stock INTEGER NOT NULL
);

-- Selanjutnya, buat tabel "users".
CREATE TABLE users (
    id serial PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    deposit_amount NUMERIC DEFAULT 0
);

-- Terakhir, buat tabel "rental_historys".
CREATE TABLE rental_histories (
    id serial PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    book_id INTEGER REFERENCES books(id),
    rental_date DATE NOT NULL,
    return_date DATE NOT NULL,
    rental_cost NUMERIC(10, 2) NOT NULL
);



-- Menambahkan Kategori Buku
INSERT INTO categories (name)
VALUES
    ('Fiksi'),
    ('Non-Fiksi'),
    ('Pendidikan'),
    ('Sejarah'),
    ('Sastra');

-- Menambahkan Data Buku
INSERT INTO books (title, author, publication_year, category_id, stock)
VALUES
    ('Laskar Pelangi', 'Andrea Hirata', 2005, 1, 30),
    ('Panduan Investasi Saham', 'Robert Johnson', 2016, 2, 12),
    ('Kisah Nyata Petani Indonesia', 'Budi Hartono', 2011, 3, 20),
    ('Bumi Manusia', 'Pramoedya Ananta Toer', 1980, 4, 25),
    ('Cerita Rakyat Nusantara', 'Eka Kurniawan', 2009, 5, 14);


