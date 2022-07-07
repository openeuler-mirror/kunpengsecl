CREATE TABLE client (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    regtime TIMESTAMPTZ,
    deleted BOOLEAN,
    info JSONB,
    ikcert TEXT
);

CREATE TABLE report (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    clientid BIGINT,
    createtime TIMESTAMPTZ,
    validated BOOLEAN,
    trusted BOOLEAN,
    quoted TEXT,
    signature TEXT,
    pcrlog TEXT,
    bioslog TEXT,
    imalog TEXT
);

CREATE TABLE base (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    clientid BIGINT,
    basetype CHAR(10), 
    uuid CHAR(64),
    createtime TIMESTAMPTZ,
    enabled BOOLEAN,  
    name TEXT,
    pcr TEXT,
    bios TEXT,
    ima TEXT
);

CREATE TABLE device_key(
    id BIGSERIAL PRIMARY KEY NOT NULL,
    device_cert TEXT,
    registered BOOLEAN,
    trusted BOOLEAN,
    register_time TIMESTAMPTZ,
    client_info TEXT
);

CREATE TABLE akey_cert(
    id BIGSERIAL PRIMARY KEY NOT NULL,
    device_id BIGSERIAL NOT NULL REFERENCES device_key(id),
    create_time TIMESTAMPTZ,
    expire_time TIMESTAMPTZ,
    ak_certificate TEXT,
    available BOOLEAN
);