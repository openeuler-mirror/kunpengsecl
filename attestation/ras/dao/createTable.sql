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
    alg_name VARCHAR(16),
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
                                      alg_name VARCHAR(16),
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
