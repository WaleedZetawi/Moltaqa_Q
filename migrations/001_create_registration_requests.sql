/* 001_create_registration_requests.sql */
CREATE TABLE IF NOT EXISTS registration_requests (
    id          SERIAL PRIMARY KEY,
    role        VARCHAR(12)  NOT NULL CHECK (role IN ('student','supervisor')),
    reg_number  VARCHAR(50),
    name        VARCHAR(100) NOT NULL,
    email       VARCHAR(100) UNIQUE NOT NULL,
    status      VARCHAR(10)  DEFAULT 'pending'
                 CHECK (status IN ('pending','approved','rejected')),
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
