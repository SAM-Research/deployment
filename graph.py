import networkx as nx
import matplotlib.pyplot as plt
import json
from pprint import pprint
import numpy as np
import argparse


def clustered_layout(G: nx.Graph, offset_v: float):
    from networkx.algorithms.community import greedy_modularity_communities

    communities = list(greedy_modularity_communities(G))
    pos = {}
    offset = np.array([0.0, 0.0])

    for community in communities:
        subG = G.subgraph(community)
        sub_pos = nx.circular_layout(subG)
        for node in sub_pos:
            pos[node] = sub_pos[node] + offset
        offset += np.array([offset_v, offset_v])  # space between clusters

    return pos


def friends(
    graph: dict[str, set],
    edges: tuple[list, list],
    labels: dict[tuple, int],
    title: str,
):
    denim_edges, normal_edges = edges
    G = nx.Graph()
    for u, neighbors in graph.items():
        for v in neighbors:
            weight = labels.get((u, v), labels.get((v, u), 1))
            G.add_edge(u, v, weight=weight)

    pos = clustered_layout(G, 2.0)

    plt.figure(figsize=(8, 6))
    nx.draw_networkx_nodes(G, pos, node_color="#e1d5e7")
    nx.draw_networkx_labels(G, pos)

    nx.draw_networkx_edges(
        G, pos, edgelist=normal_edges, edge_color="black", style="solid"
    )

    nx.draw_networkx_edges(
        G, pos, edgelist=denim_edges, edge_color="black", style="dashed"
    )
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_color="red")
    plt.title(title)
    plt.axis("off")
    plt.show()


def edges(report: dict, total_msgs: dict):
    graph = {k: set(v["friends"]) for k, v in report["clients"].items()}
    normal_edges = []
    denim_edges = []
    seen_edges = set()
    ips: dict = report["ipAddresses"]
    for n, edges in graph.items():
        friends: dict[str, dict] = report["clients"][n]["friends"]
        for edge in edges:
            is_denim = friends[edge]["denim"]
            if (n, edge) in seen_edges:
                continue
            nl = len_label(ips[n], total_msgs)
            el = len_label(ips[edge], total_msgs)
            uv = (nl, el)
            if is_denim:
                denim_edges.append(uv)
            else:
                normal_edges.append(uv)
            seen_edges.add((edge, n))
            seen_edges.add((n, edge))
    return denim_edges, normal_edges


def make_ip_graph(report: dict, total_msgs: dict):
    graph = {k: set(v["friends"]) for k, v in report["clients"].items()}
    ips: dict = report["ipAddresses"]
    ip_graph = dict()
    for n, edges in graph.items():
        nl = len_label(ips[n], total_msgs)
        ip_graph[nl] = {len_label(ips[e], total_msgs) for e in edges}
    return ip_graph


def len_label(n: str, labels: dict):
    return f"{n}\n{labels[n]}"


def make_labels(report: dict, total_msgs: dict):
    graph = {k: set(v["friends"]) for k, v in report["clients"].items()}
    ips: dict = report["ipAddresses"]
    labels = dict()

    for n, edges in graph.items():
        messages: list[dict] = report["reports"][n]["messages"]

        for edge in edges:
            msgs = [1 for m in messages if m["from"] == edge or m["to"] == edge]
            nl = len_label(ips[n], total_msgs)
            el = len_label(ips[edge], total_msgs)
            edge_1 = (nl, el)
            edge_2 = (el, nl)
            if edge_1 in labels:
                labels[edge_1] += len(msgs)
            elif edge_2 in labels:
                labels[edge_2] += len(msgs)
            else:
                labels[edge_1] = len(msgs)

    return labels


def total_msgs(report: dict):
    graph = {k: set(v["friends"]) for k, v in report["clients"].items()}
    ips: dict = report["ipAddresses"]
    return {ips[n]: len(report["reports"][n]["messages"]) for n in graph}


def best_friends(report: dict):
    clients: dict[str, dict] = report["clients"]
    ips: dict = report["ipAddresses"]
    friendslist = dict()
    for client, data in clients.items():
        friends: list[dict] = list(data["friends"].values())
        friend = max(friends, key=lambda x: x["frequency"])
        friendslist[ips[client]] = ips[friend["username"]]
    return friendslist


def popularity(friends: dict[str, str]):
    pops = dict()
    for f in friends.values():
        if f not in pops:
            pops[f] = 0
        pops[f] += 1

    return pops


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    args = parser.parse_args()
    with open(f"./{args.name}/reports/report.json", "r") as f:
        data = json.load(f)
        print("Clients:", len(data["clients"]))
        print("Reports:", len(data["reports"]))
        msg_lens = total_msgs(data)
        edge_tuple = edges(data, msg_lens)
        graph = make_ip_graph(data, msg_lens)
        label = make_labels(data, msg_lens)
        besties = best_friends(data)
        popularity_table = popularity(besties)
        print("-- Client Friends --")
        for c, f in sorted(besties.items(), key=lambda x: int(x[0].split(".")[-1])):
            print(f"{c} -> {f}")

        print("\n-- Client Popularity --")
        for c, p in sorted(popularity_table.items(), key=lambda x: x[1], reverse=True):
            print(f"{c}: {p}")

        friends(graph, edge_tuple, label, args.name)
