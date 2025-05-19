import docker
import subprocess
from pathlib import Path
import docker.models.containers
import json
import sys
import time
import pyshark
from collections import defaultdict

import pyshark.packet
import pyshark.packet.packet
import csv
import shutil
import gzip
import io

network_driver = {"bridge": "br"}


def get_net(client: docker.DockerClient, name: str):
    for net in client.networks.list():
        if net.name == f"{name}_default":
            driver = network_driver[net.attrs["Driver"]]
            net_id = net.attrs["Id"][:12]
            return f"{driver}-{net_id}"
    return None


def containers(
    client: docker.DockerClient, name: str
) -> list[docker.models.containers.Container]:
    containers: list[docker.models.containers.Container] = []
    for container in client.containers.list():
        if container.labels.get("com.docker.compose.project") != name:
            continue
        containers.append(container)
    return containers


def is_compose_running(client: docker.DockerClient, name: str):
    project = containers(client, name)
    if len(project) == 0:
        return False
    return all(c.status == "running" for c in project)


def close_docker_compose(client: docker.DockerClient, name: str):
    project = containers(client, name)
    for container in project:
        container.remove(force=True)


def start_docker_compose(denim: bool):
    if denim:
        compose = "denim.yml"
    else:
        compose = "sam.yml"
    try:
        subprocess.run(
            ["docker", "compose", "-f", f"{compose}", "up", "-d"], check=True
        )
    except:
        return False
    return True


def container_ips(client: docker.DockerClient, name: str) -> dict[str, str]:
    addrs: dict[str, str] = dict()
    for container in containers(client, name):
        network_settings = container.attrs["NetworkSettings"]
        networks = network_settings["Networks"]
        net = f"{name}_default"
        if net not in networks:
            continue
        network = networks[net]
        addr = network["IPAddress"]

        addrs[container.name] = addr

    trim = lambda k: k if "-" not in k else k.split("-")[1]

    return {trim(k): v for k, v in addrs.items()}


def start_clients(denim: bool, amount: int) -> bool:
    if denim:
        compose = "denim.yml"
    else:
        compose = "sam.yml"
    try:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                f"{compose}",
                "up",
                "--scale",
                f"client={amount}",
                "-d",
            ],
            check=True,
        )
    except:
        return False
    return True


def start_tshark(client: docker.DockerClient, name: str, out: str):
    net = get_net(client, name)

    cmd = ["tshark", "-i", net, "-F", "pcapng", "-w", out]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_time(report: dict[str, dict]):
    return float(min(r["startTime"] for r in report["reports"].values()))


def sam_pcap_to_list(file: str) -> list[dict]:
    cap = pyshark.FileCapture(file)
    valid_packets = []
    packet: pyshark.packet.packet.Packet
    for i, packet in enumerate(cap):
        time = float(packet.sniff_timestamp)
        if not any(x in packet for x in {"HTTP", "IP"}):
            continue

        if "TCP" in packet:
            src_port, dst_port = packet.tcp.srcport, packet.tcp.dstport
        elif "UDP" in packet:
            src_port, dst_port = packet.udp.srcport, packet.udp.dstport
        else:
            src_port, dst_port = "", ""

        if "HTTP" in packet and hasattr(packet.http, "request_uri"):
            info = packet.http.request_uri
        else:
            info = "TLS"

        row = {
            "No.": i,
            "Time": time,
            "Source": packet.ip.src,
            "Destination": packet.ip.dst,
            "Protocol": packet.transport_layer,
            "Length": packet.length,
            "Info": info,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        valid_packets.append(row)
    return valid_packets


def filter_traffic(data: list[dict], start: float) -> list[dict]:
    last_sync = 0
    for i, packet in enumerate(data):
        if packet["Info"] == "/sync":
            last_sync = i
    last_sync += 10

    new_packets = []
    for packet in data[last_sync:]:
        time_rel = packet["Time"] - start
        packet["Time"] = time_rel
        new_packets.append(packet)
    return new_packets


def create_traffic_csv(data: list[dict], file: str):

    if len(data) > 0:
        with open(file, "w") as f:
            writer = csv.DictWriter(
                f, fieldnames=list(data[0].keys()), quoting=csv.QUOTE_ALL
            )
            writer.writeheader()
            writer.writerows(data)


def create_analysis_config(report: dict[str, dict[str, dict]], ips: dict[str, str]):
    server_ip = ips["gateway"]

    for name, client in report["clients"].items():
        friends: list[dict] = list(client["friends"].values())

        for friend in friends:
            if not friend["denim"]:
                continue
            return {
                "target": report["ipAddresses"][name],
                "actual": report["ipAddresses"][friend["username"]],
                "epoch": 1,
                "server": server_ip,
            }
    return None


if __name__ == "__main__":
    project_name = Path(__file__).parent.name
    client = docker.from_env()

    with open("./config/driver.json", "r") as f:
        config: dict = json.load(f)
        is_denim: bool = config["denim"]
        clients: int = config["clients"]
        dispatch: str = config["dispatchAddress"]
        report: Path = Path(config["reportPath"])

    if report.exists():

        while True:
            answer = input(
                "A Report already exists, do you want to overwrite it? [y/n]: "
            )
            if answer in {"y", "yes"}:
                break
            if answer in {"n", "no"}:
                print("Goodbye!")
                sys.exit(0)
        report.unlink()
        traffic = Path("./reports/traffic.pcap")
        if traffic.exists():
            traffic.unlink()

    net = get_net(client, project_name)
    if is_compose_running(client, project_name):
        print("Closing docker compose...")
        close_docker_compose(client, project_name)

    print("Starting docker compose...")
    start = start_docker_compose(is_denim)
    if not start:
        print("Failed to start docker compose")
        sys.exit(1)

    ips = container_ips(client, project_name)

    print("Starting tshark...")
    pcap = f"./reports/traffic.pcap"
    tshark = start_tshark(client, project_name, pcap)
    if tshark.poll() is not None:
        print("Failed to start tshark")
        sys.exit(1)

    print("Starting clients...")
    if not start_clients(is_denim, clients):
        print("Failed to start clients")
        sys.exit(1)

    print("Waiting for clients to finish...")
    while True:
        time.sleep(0.25)
        if report.exists():
            tshark.terminate()

            break
    print("Closing docker compose...")
    close_docker_compose(client, project_name)

    print("Reading report...")
    with open(report, "r") as f:
        report_data: dict = json.load(f)

    print("Reading traffic data (this might take a while)...")
    traffic_data = sam_pcap_to_list(pcap)

    print("Filtering traffic data...")
    start = start_time(report_data)
    filtered = filter_traffic(traffic_data, start)

    data_out = Path("./analysis/data.csv")
    print(f"Saving Filtered traffic data as '{data_out}'...")
    data_out.parent.mkdir(exist_ok=True)
    create_traffic_csv(filtered, data_out)

    print("Saving Analysis config...")
    analysis_file = Path("./analysis/settings.json")
    acfg = create_analysis_config(
        report_data,
        ips,
    )
    with open(analysis_file, "w") as f:
        json.dump(acfg, f, indent=2)

    print("Done!")
