CREATE TABLE users(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    email TEXT UNIQUE NOT NULL
);

CREATE TABLE chirps(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    body TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE
);
