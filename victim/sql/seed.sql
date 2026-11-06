-- QueryShield demo seed data. ALL FAKE. Localhost only.
--
-- Passwords are hashed with SHA2(x, 256) so the login query compares hashes,
-- never plaintext. The plaintext values below are obviously-fake demo strings.

INSERT INTO users (username, email, password_hash, is_admin) VALUES
  ('admin',  'admin@queryshield.invalid',  SHA2('ADMIN-demo-not-real-9f3c', 256), 1),
  ('alice',  'alice@queryshield.invalid',  SHA2('alice-demo-not-real-2a17', 256), 0),
  ('bob',    'bob@queryshield.invalid',    SHA2('bob-demo-not-real-7c42',   256), 0),
  -- apostrophe in the email is intentional: it is a benign value the proxy
  -- must NOT flag once we get to false-positive testing.
  ('obrien', 'obrien@queryshield.invalid', SHA2('obrien-demo-not-real-5d08',256), 0);

INSERT INTO products (name, price, description) VALUES
  ('Red Running Shoes',   79.99, 'Lightweight trainers'),
  ('Blue Yoga Mat',       24.50, 'Non-slip surface'),
  -- "Union" here is a benign English word in product data, kept on purpose
  -- so later we can show the detector does not flag it.
  ('Union Station Mug',   12.00, 'Ceramic, 350ml'),
  ('Steel Water Bottle',  18.75, '750ml insulated'),
  ('Wireless Mouse',      29.99, 'USB-C receiver');

INSERT INTO secrets (name, value) VALUES
  ('api_key',      'FAKE-sk-queryshield-DEMO-0000-DO-NOT-USE'),
  ('internal_url', 'FAKE-http://internal.invalid/admin'),
  ('flag',         'FAKE{queryshield_union_based_extraction_demo}');
