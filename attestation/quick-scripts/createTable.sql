CREATE TABLE client (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    regtime TIMESTAMPTZ,
    registered BOOLEAN,
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
    basetype TEXT, 
    uuid TEXT,
    createtime TIMESTAMPTZ,
    enabled BOOLEAN,  
    name TEXT,
    pcr TEXT,
    bios TEXT,
    ima TEXT
);

CREATE TABLE tareport (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    clientid BIGINT,
    createtime TIMESTAMPTZ,
    validated BOOLEAN,
    trusted BOOLEAN,
    uuid TEXT,
    value TEXT
);

CREATE TABLE tabase(
    id BIGSERIAL PRIMARY KEY NOT NULL,
    clientid BIGINT,
    uuid TEXT,
    createtime TIMESTAMPTZ,
    enabled BOOLEAN,
    name TEXT,  
    valueinfo TEXT
);

CREATE TABLE keyinfo (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    taid CHAR(36),
    keyid CHAR(36),
    ciphertext TEXT
);

CREATE TABLE pubkeyinfo (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    deviceid BIGINT,
    pubkeycert TEXT
);
