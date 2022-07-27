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
    basetype CHAR(10), 
    uuid CHAR(64),
    createtime TIMESTAMPTZ,
    enabled BOOLEAN,  
    name TEXT,
    pcr TEXT,
    bios TEXT,
    ima TEXT
);