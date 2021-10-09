CREATE TABLE trust_report (
                              report_id BIGSERIAL PRIMARY KEY NOT NULL,
                              client_id BIGINT NOT NULL,
                              report_time TIMESTAMPTZ,
                              pcr_quote TEXT,
                              client_info_id BIGINT DEFAULT NULL
)

CREATE TABLE trust_report_pcr_info(
                                      report_id BIGINT NOT NULL REFERENCES trust_report(report_id),
                                      algorithm INTEGER,
                                      pcr_id INTEGER NOT NULL,
                                      pcr_value TEXT,
                                      PRIMARY KEY(report_id, pcr_id)
)

CREATE TABLE trust_report_manifest(
                                      report_id BIGINT NOT NULL REFERENCES trust_report(report_id),
                                      type VARCHAR(128),
                                      index INTEGER NOT NULL,
                                      name VARCHAR(128),
                                      value TEXT,
                                      detail TEXT,
                                      PRIMARY KEY(report_id, type, index)
)

CREATE TABLE client_info(
                            client_info_id BIGINT NOT NULL REFERENCES client_info_id(id),
                            name VARCHAR(128) NOT NULL,
                            value TEXT,
                            PRIMARY KEY(client_info_id, name)
)

CREATE TABLE register_client (
                                 client_id BIGSERIAL NOT NULL PRIMARY KEY,
                                 client_info_id BIGINT NOT NULL,
                                 register_time TIMESTAMPTZ,
                                 challenge TEXT,
                                 ak_certificate TEXT
)

CREATE TABLE client_info_id (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    online BOOLEAN
)