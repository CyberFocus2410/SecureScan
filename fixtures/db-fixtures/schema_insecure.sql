-- Insecure SQL Migration Fixture
CREATE TABLE customer_records (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    pan_number VARCHAR(10), -- Plaintext Tax ID (PAN)
    passport_number VARCHAR(20), -- Plaintext Passport
    raw_password VARCHAR(255)
);

-- Flaw 6: Overly broad permissions granted to PUBLIC
GRANT ALL PRIVILEGES ON TABLE customer_records TO PUBLIC;
GRANT ALL ON DATABASE app_prod TO PUBLIC;

-- Flaw 7: Missing Row Level Security (RLS) on multi-tenant table
-- ALTER TABLE customer_records ENABLE ROW LEVEL SECURITY; (omitted)
