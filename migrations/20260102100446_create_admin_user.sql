-- Add migration script here

INSERT INTO users (id, email, name, role)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'Admin',
    'admin'
)
ON CONFLICT (id) DO NOTHING;
