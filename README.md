# OIDC Validator for PostgreSQL 18
This project aims to provide basic OIDC validator library to enable using the [oauth bearer mechanism](https://www.postgresql.org/docs/18/auth-oauth.html).

Tested on Ubuntu and ArchLinux x86_64

## Setup
Make sure you have rust installed and build tools like gcc installed.

Ubuntu packages:
```shell
apt install curl git wget libcurl4-openssl-dev build-essential clang libreadline-dev zlib1g-dev flex bison libxml2-dev libxslt-dev libssl-dev libxml2-utils xsltproc ccache pkg-config
```

## Compile Postgres 18
**Note: Do not run these commands with root user!**
```shell
# Download the postgresql, in this example it would be downloaded in your home folder under postgresql/source
export PG_VERSION="18.0"
export PG_SOURCE_DIR="${HOME}/postgresql/source"
export PG_INST_DIR_PREFIX="${HOME}/postgresql/${PG_VERSION}"
export PATH=${PG_INST_DIR_PREFIX}/bin:$PATH

mkdir -p "$PG_SOURCE_DIR"
cd "$PG_SOURCE_DIR"

# Download postgres
wget https://ftp.postgresql.org/pub/source/v${PG_VERSION}/postgresql-${PG_VERSION}.tar.gz
tar zxf "postgresql-${PG_VERSION}.tar.gz"
cd "postgresql-${PG_VERSION}"

# Configure and compile postgresql
# Make sure you have all necessary dependencies as mentioned here https://wiki.postgresql.org/wiki/Compile_and_Install_from_source_code
./configure --prefix=${PG_INST_DIR_PREFIX} --with-openssl --with-libcurl
make -j$(nproc)
make install
```

## Compile oidc_validator
Make sure you have rust installed https://rustup.rs/
```shell
cd "${HOME}/postgresql"
# Clone the oidc validator repository
git clone https://github.com/UnAfraid/oidc_validator
cd oidc_validator

# Install cargo-pgrx
cargo install --locked cargo-pgrx
cargo pgrx init --pg18 $(which pg_config)

# Build the validator plugin
PG_CONFIG=$(which pg_config) cargo build --release

# Copy the release to postgresql library folder 
cp target/release/liboidc_validator.so $(pg_config --pkglibdir)/oidc_validator.so
```

## PostgreSQL OAuth Setup
Create new postgres cluster
```shell
cd "${HOME}/postgresql"
initdb -D oauth_data
```

Now edit oauth_data/pg_hba.conf
```
# OAuth2 authentication (IPv4)
host all all 0.0.0.0/0 oauth issuer="https://your-oauth-server" scope="openid profile"

# OAuth2 authentication (IPv6)
host all all ::/0 oauth issuer="https://your-oauth-server" scope="openid profile"
```

Enable the oidc_validator in oauth_data/postgresql.conf
```diff
oauth_validator_libraries = 'oidc_validator'	# comma-separated list of trusted validator modules
```

## Configuration
The configuration is provided through the following environment variables:

| Name                    | Description                                         |
|-------------------------|-----------------------------------------------------|
| POSTGRES_OIDC_ISSUER    | OIDC Issuer url (excluding the well-known path)     |
| POSTGRES_OIDC_CLIENT_ID | OIDC Application client id                          |
| POSTGRES_OIDC_AUDIENCE  | OIDC Application audience (typically the client id) |


## Start postgresql
```shell
pg_ctl -D oauth_data -l postgresql.log start
```


## Relevant links
* https://www.postgresql.org/docs/18/auth-oauth.html
* https://www.postgresql.org/docs/current/sasl-authentication.html#SASL-OAUTHBEARER
* https://www.enterprisedb.com/blog/preview-postgresql-18s-oauth2-authentication-2-building-custom-oauth2-validator-rust