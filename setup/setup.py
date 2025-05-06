import os
from pathlib import Path
from argparse import ArgumentParser
import sys
import json
import yaml


def generate_private_key(out_path: Path):
    return os.system(f'openssl genrsa -out "{out_path}" 2048')


def generate_ca_cert(config_path: Path, key_path: Path, days: int, out_path: Path):
    cmd = (
        f"openssl req -x509 -new -nodes -key {key_path} -sha256 -days {days} "
        f"-out {out_path} -config {config_path} -extensions v3_ca"
    )
    return os.system(cmd)


def generate_cert_signing_request(private_key: Path, out_path: Path, config_path: Path):
    cmd = f"openssl req -new -key {private_key} -out {out_path} -config {config_path}"
    return os.system(cmd)


def sign_cert(
    signing_req_path: Path,
    ca_cert_path: Path,
    ca_key_path: Path,
    out_path: Path,
    days: int,
    config_path: Path,
):
    cmd = (
        f"openssl x509 -req -in {signing_req_path} -CA {ca_cert_path} -CAkey {ca_key_path} "
        f"-CAcreateserial -out {out_path} -days {days} -sha256 -extfile {config_path} "
        f"-extensions v3_req"
    )
    return os.system(cmd)


def generate_certifacte(
    name: str,
    outdir: Path,
    ca_key: Path,
    ca_cert: Path,
    config: Path,
    days: int,
):

    cert_dir = outdir / name
    cert_dir.mkdir(exist_ok=True)
    file = cert_dir / name
    key = file.with_suffix(".key")
    cert = file.with_suffix(".crt")
    csr = file.with_suffix(".csr")
    if generate_private_key(key) > 0:
        return (None, None)

    if generate_cert_signing_request(key, csr, config) != 0:
        return (None, None)
    if sign_cert(csr, ca_cert, ca_key, cert, days, config) != 0:
        return (None, None)
    return key, cert


def generate_certificate_authority(name: str, outdir: Path, config: Path, days: int):
    cert_dir = outdir / name
    cert_dir.mkdir(exist_ok=True)
    file = cert_dir / name
    key = file.with_suffix(".key")
    cert = file.with_suffix(".crt")
    if generate_private_key(key) != 0:
        return (None, None)
    if generate_ca_cert(config, key, days, cert) != 0:
        return (None, None)
    return key, cert


def create_proxy_tls(
    root_outdir: Path,
    ca_cert: Path,
    proxy_cert: Path,
    proxy_key: Path,
    client_cert: Path | None,
    client_key: Path | None,
    mtls: bool,
) -> dict:
    proxy_tls = {
        "caCertPath": "/" + ca_cert.relative_to(root_outdir).as_posix(),
        "proxyCertPath": "/" + proxy_cert.relative_to(root_outdir).as_posix(),
        "proxyKeyPath": "/" + proxy_key.relative_to(root_outdir).as_posix(),
        "proxyMtls": mtls,
    }
    if mtls:
        proxy_tls["proxyClient"] = {
            "certPath": "/" + client_cert.relative_to(root_outdir).as_posix(),
            "keyPath": "/" + client_key.relative_to(root_outdir).as_posix(),
        }
    return proxy_tls


def create_server_tls(
    root_outdir: Path, cert: Path, key_path: Path, ca_cert: Path, mtls: bool
):
    server_tls = {
        "certPath": "/" + cert.relative_to(root_outdir).as_posix(),
        "keyPath": "/" + key_path.relative_to(root_outdir).as_posix(),
    }
    if mtls:
        server_tls["caCertPath"] = "/" + ca_cert.relative_to(root_outdir).as_posix()
    return server_tls


def generate_tls(root_outdir: Path, cert_cnf: Path, days: int, mtls: bool):
    outdir = root_outdir / "certs"
    outdir.mkdir(exist_ok=True)
    ca_key, ca_cert = generate_certificate_authority("root", outdir, cert_cnf, days)
    if ca_key is None:
        print("Failed to generate server certificates!")
        sys.exit(1)

    server_key, server_cert = generate_certifacte(
        "sam", outdir, ca_key, ca_cert, cert_cnf, days
    )
    if server_key is None:
        print("Failed to generate server certificates!")
        sys.exit(1)
    proxy_key, proxy_cert = generate_certifacte(
        "proxy", outdir, ca_key, ca_cert, cert_cnf, days
    )
    if proxy_key is None:
        print("Failed to generate proxy certificates!")
        sys.exit(1)

    nginx_cert, _ = generate_certifacte(
        "nginx", outdir, ca_key, ca_cert, cert_cnf, days
    )
    if nginx_cert is None:
        print("Failed to generate nginx certificates!")
        sys.exit(1)

    client_key, client_cert = (None, None)
    if mtls:
        client_key, client_cert = generate_certifacte(
            "proxy_client", outdir, ca_key, ca_cert, cert_cnf, days
        )
        if client_key is None:
            print("Failed to generate proxy client certificates!")
            sys.exit(1)
        ngnix_cert, _ = generate_certifacte(
            "nginx_client", outdir, ca_key, ca_cert, cert_cnf, days
        )
        if ngnix_cert is None:
            print("Failed to generate ngnix client certificates!")
            sys.exit(1)

    proxy_tls = create_proxy_tls(
        root_outdir, ca_cert, proxy_cert, proxy_key, client_cert, client_key, mtls
    )
    server_tls = create_server_tls(root_outdir, server_cert, server_key, ca_cert, mtls)
    return server_tls, proxy_tls


def create_setupsql(link_secret: str, provision_timeout: int):
    return f"""INSERT INTO device_link_info
    (id, link_secret, provision_expire_seconds)
VALUES
    (1, '{link_secret}', {provision_timeout});"""


def create_nginx(port: str, is_mtls: bool, path: Path):
    is_tls = port == "443"

    listen = f"{port} ssl" if is_tls else port
    tls_cfg = ""
    mtls_cfg = ""
    protocol = "http"
    if is_tls:
        protocol = "https"
        tls_cfg = """ssl_certificate /etc/nginx/certs/nginx/nginx.crt;
        ssl_certificate_key /etc/nginx/certs/nginx/nginx.key;"""
    if is_mtls:
        mtls_cfg = """proxy_ssl_certificate /etc/nginx/certs/nginx_client/nginx_client.crt;
            proxy_ssl_certificate_key /etc/nginx/certs/nginx_client/nginx_client.key;
            proxy_ssl_trusted_certificate /etc/nginx/certs/root/root.crt;
            proxy_ssl_verify on;
            proxy_ssl_name localhost;
            proxy_ssl_server_name on;"""

    with open(path, "r") as f:
        temp = f.read()
        return (
            temp.replace("<PROTOCOL>", protocol)
            .replace("<PORT>", port)
            .replace("<TLS>", tls_cfg)
            .replace("<MTLS>", mtls_cfg)
            .replace("<LISTEN>", listen)
        )


def extract_connection_url(compose: dict[str, str]):
    sam_db = compose["services"]["sam_db"]
    env = sam_db["environment"]
    url = sam_db["container_name"]
    user = env["POSTGRES_USER"]
    pwd = env["POSTGRES_PASSWORD"]
    db = env["POSTGRES_DB"]

    return f"postgres://{user}:{pwd}@{url}:5432/{db}"


def create_docker_compose(
    tls: bool,
    mtls: bool,
    expose_sam: int | None,
    expose_dispatch: int | None,
    port: int,
    root_outdir: Path,
    is_denim: bool,
    compose_path: Path,
    out_path: Path,
):
    gateway_tls = ["./certs/nginx:/etc/nginx/certs/nginx"]
    gateway_mtls = [
        "./certs/nginx_client:/etc/nginx/certs/nginx_client",
        "./certs/root/root.crt:/etc/nginx/certs/root/root.crt",
    ]
    denim_tls = ["./certs/proxy:/certs/proxy"]
    denim_mtls = [
        "./certs/proxy_client:/certs/proxy_client",
        "./certs/root/root.crt:/certs/root/root.crt",
    ]
    sam_tls = ["./certs/sam:/certs/sam"]
    sam_mtls = ["./certs/root/root.crt:/certs/root/root.crt"]

    with open(compose_path, "r") as f:
        config: dict = yaml.safe_load(f)

    gateway_volumes: list = config["services"]["gateway"]["volumes"]
    if is_denim:
        denim_volumes: list = config["services"]["denim_proxy"]["volumes"]
    sam_volumes: list = config["services"]["sam_server"]["volumes"]
    dispatch_volumes: list = config["services"]["sam_dispatch"]["volumes"]
    if tls:
        gateway_volumes.extend(gateway_tls)
        if is_denim:
            denim_volumes.extend(denim_tls)
        sam_volumes.extend(sam_tls)
    if mtls:
        gateway_volumes.extend(gateway_mtls)
        if is_denim:
            denim_volumes.extend(denim_mtls)
        sam_volumes.extend(sam_mtls)
    if expose_sam is not None:
        config["services"]["gateway"]["ports"] = [f"{expose_sam}:{port}"]
    if expose_dispatch is not None:
        config["services"]["sam_dispatch"]["ports"] = [f"{expose_dispatch}:80"]

    report_dir = root_outdir / "reports"
    report_dir.mkdir(exist_ok=True)
    dispatch_volumes.append("./reports:/reports")

    conn = extract_connection_url(config)

    with open(out_path, "w") as f:
        yaml.safe_dump(config, f, indent=2)
    return conn


def download_initsql(outdir: Path):
    outpath = outdir / Path("initdb/init.sql")
    outpath.parent.mkdir(exist_ok=True)
    return os.system(
        f"curl -o {outpath} https://raw.githubusercontent.com/SAM-Research/sam-instant-messenger/refs/heads/main/server/database/init.sql"
    )


def create_cert_cnf(
    outdir: Path,
    country: str,
    state: str,
    locality: str,
    organization: str,
    unit: str,
    common_name: str,
):
    with open(Path(__file__).parent / "files/cert.cnf", "r") as f:
        temp = (
            f.read()
            .replace("<C>", country)
            .replace("<ST>", state)
            .replace("<L>", locality)
            .replace("<O>", organization)
            .replace("<OU>", unit)
            .replace("<CN>", common_name)
        )
    outfile = outdir / "certs" / "cert.cnf"
    outfile.parent.mkdir(exist_ok=True)
    with open(outfile, "w") as f:
        f.write(temp)
    return outfile


if __name__ == "__main__":

    parser = ArgumentParser(
        "setup",
        description="Generate project structure for denim-on-sam infrastructure",
    )
    parser.add_argument("outdir")
    parser.add_argument("config")

    args = parser.parse_args()
    root_outdir = Path(args.outdir)
    config = Path(args.config)
    days = 365

    SAM_SERVER_IP = "sam_server"
    DENIM_PROXY_IP = "denim_proxy"

    if not config.exists():
        print("Config does not exist!")
        sys.exit(1)

    expose_dispatch: str | None = None
    with open(config, "r") as f:
        master_config: dict = json.load(f)
        config = master_config["samnet"]
        # modify dispatcher config
        dispatch_config = master_config["samDispatch"]
        dispatch_config["address"] = "0.0.0.0:80"
        if "expose" in dispatch_config:
            expose_dispatch = dispatch_config["expose"]
            del dispatch_config["expose"]

    config_dir = root_outdir / "config"
    initdb_dir = root_outdir / "initdb"
    ngnix_dir = root_outdir / "nginx"

    root_outdir.mkdir(exist_ok=True)
    config_dir.mkdir(exist_ok=True)
    initdb_dir.mkdir(exist_ok=True)
    ngnix_dir.mkdir(exist_ok=True)

    server_tls, proxy_tls = None, None
    mtls = False
    tls = False
    if "tls" in config:
        tls = True
        mtls = config["tls"]["mtls"]
        cert_config = config["tls"]["config"]
        cert_cnf = create_cert_cnf(
            root_outdir,
            cert_config["C"],
            cert_config["ST"],
            cert_config["L"],
            cert_config["O"],
            cert_config["OU"],
            cert_config["CN"],
        )
        server_tls, proxy_tls = generate_tls(root_outdir, cert_cnf, days, mtls)
    port = "80" if server_tls is None else "443"

    in_compose = Path(__file__).parent / "files/docker-compose.yml"
    denim_compose = root_outdir / "docker-compose.yml"
    db_url = create_docker_compose(
        tls,
        mtls,
        config.get("expose", None),
        expose_dispatch,
        port,
        root_outdir,
        True,
        in_compose,
        denim_compose,
    )

    in_sam_compose = Path(__file__).parent / "files/sam-docker-compose.yml"
    sam_compose = root_outdir / "sam-docker-compose.yml"
    db_url = create_docker_compose(
        tls,
        mtls,
        config.get("expose", None),
        expose_dispatch,
        port,
        root_outdir,
        False,
        in_sam_compose,
        sam_compose,
    )

    server_config = {
        "databaseUrl": db_url,
        "address": f"0.0.0.0:{port}",
        "messageBufferSize": config["bufferSize"],
        "logging": config.get("logging", ""),
    }
    proxy_config = {
        "databaseUrl": db_url,
        "samAddress": f"{SAM_SERVER_IP}:{port}",
        "denimProxyAddress": f"0.0.0.0:{port}",
        "deniableRatio": config["deniableRatio"],
        "channelBufferSize": config["bufferSize"],
        "logging": config.get("logging", ""),
    }
    if server_tls is not None:
        server_config["tls"] = server_tls
    if proxy_tls is not None:
        proxy_config["tls"] = proxy_tls

    with open(config_dir / "denim.json", "w") as f:
        json.dump(proxy_config, f, indent=2)
    with open(config_dir / "sam.json", "w") as f:
        json.dump(server_config, f, indent=2)
    with open(config_dir / "dispatch.json", "w") as f:
        json.dump(dispatch_config, f, indent=2)

    with open(initdb_dir / "setup.sql", "w") as f:
        f.write(create_setupsql(config["linkSecret"], config["provisionTimeout"]))

    if download_initsql(root_outdir) != 0:
        print("Failed to download init.sql")
        sys.exit(1)

    with open(ngnix_dir / "nginx.conf", "w") as f:
        temp = Path(__file__).parent / "files/nginx.conf"
        f.write(create_nginx(port, mtls, temp))
    with open(ngnix_dir / "sam-nginx.conf", "w") as f:
        temp = Path(__file__).parent / "files/sam-nginx.conf"
        f.write(create_nginx(port, mtls, temp))

    print("Done!")
