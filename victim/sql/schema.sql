-- QueryShield demo database schema.
--
-- ============================================================================
--  VULNERABLE ON PURPOSE. Do not deploy. Localhost only. All data is FAKE.
-- ============================================================================
--
-- Three tables that back the deliberately vulnerable demo app:
--   users    - login + profile endpoints read from here
--   products - the search endpoint reads from here
--   secrets  - the "crown jewels" a UNION-based injection tries to steal
--
-- Loaded by victim/setup_db.sh after the database has been created.

DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id            INT PRIMARY KEY AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  email         VARCHAR(128) NOT NULL,
  -- SHA2(password, 256). Passwords are FAKE and exist only so the login
  -- endpoint has something to compare against. Never real credentials.
  password_hash CHAR(64)     NOT NULL,
  is_admin      TINYINT(1)   NOT NULL DEFAULT 0
);

CREATE TABLE products (
  id          INT PRIMARY KEY AUTO_INCREMENT,
  name        VARCHAR(128)  NOT NULL,
  price       DECIMAL(10,2) NOT NULL,
  description VARCHAR(255)  NOT NULL DEFAULT ''
);

CREATE TABLE secrets (
  id    INT PRIMARY KEY AUTO_INCREMENT,
  name  VARCHAR(64)  NOT NULL,
  -- FAKE secrets. The point is to show that a working UNION injection can
  -- pull rows the endpoint never intended to expose.
  value VARCHAR(255) NOT NULL
);
