CREATE TABLE register_client (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    client_info_ver INT,
    register_time TIMESTAMPTZ,
    ak_certificate TEXT,
    online BOOLEAN,
    deleted BOOLEAN,
    base_value_ver INT
);

CREATE TABLE trust_report (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    client_id BIGINT NOT NULL REFERENCES register_client(id),
    client_info_ver INT,
    report_time TIMESTAMPTZ,
    pcr_quote BYTEA,
    verified BOOLEAN
);

CREATE TABLE trust_report_pcr_info(
    id BIGSERIAL NOT NULL,
    report_id BIGINT NOT NULL REFERENCES trust_report(id),
    pcr_id INTEGER NOT NULL,
    pcr_value TEXT,
    PRIMARY KEY(report_id, pcr_id)
);

CREATE TABLE trust_report_manifest(
    id BIGSERIAL NOT NULL,
    report_id BIGINT NOT NULL REFERENCES trust_report(id),
    index INTEGER NOT NULL,
    type VARCHAR(16),
    name TEXT,
    value TEXT,
    detail TEXT,
    PRIMARY KEY(report_id, index, type)
);

CREATE TABLE client_info(
    id BIGSERIAL NOT NULL,
    client_id BIGINT NOT NULL REFERENCES register_client(id),
    client_info_ver INT,
    name VARCHAR(128) NOT NULL,
    value TEXT,
    PRIMARY KEY(client_id, client_info_ver, name)
);

CREATE TABLE base_value_pcr_info(
                                      id BIGSERIAL NOT NULL,
                                      client_id BIGINT NOT NULL REFERENCES register_client(id),
                                      base_value_ver INT,
                                      pcr_id INTEGER NOT NULL,
                                      pcr_value TEXT
);

CREATE TABLE base_value_manifest(
                                      id BIGSERIAL NOT NULL,
                                      client_id BIGINT NOT NULL REFERENCES register_client(id),
                                      base_value_ver INT,
                                      type VARCHAR(16),
                                      name TEXT,
                                      value TEXT
);

CREATE TABLE container(
    uuid TEXT PRIMARY KEY NOT NULL,
    client_id BIGINT NOT NULL REFERENCES register_client(id),
    base_value_ver INT,
    online BOOLEAN,
    deleted BOOLEAN
);


CREATE TABLE container_base_value(
    id BIGSERIAL NOT NULL,
    container_uuid TEXT NOT NULL REFERENCES container(uuid),
    base_value_ver INT,
    name TEXT,
    value TEXT
);

CREATE TABLE device(
    id BIGINT PRIMARY KEY NOT NULL,
    client_id BIGINT NOT NULL REFERENCES register_client(id),
    base_value_ver INT,
    online BOOLEAN,
    deleted BOOLEAN
);


CREATE TABLE device_base_value(
    id BIGSERIAL NOT NULL,
    device_id BIGINT NOT NULL REFERENCES device(id),
    base_value_ver INT,
    name TEXT,
    value TEXT
);