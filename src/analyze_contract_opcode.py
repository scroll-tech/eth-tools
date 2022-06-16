import os
import sys
import json
import evmdasm
import requests
from argparse import ArgumentParser


def load_opcode_status():
    rootdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    opcode_status = {}
    with open(os.path.join(rootdir, "data", "opcode_status.tsv")) as f:
        # skip the first line
        f.readline()
        for line in f:
            opcode, _, status = line.strip().split('\t')
            opcode_status[int(opcode, 16)] = int(status)
    return opcode_status


_CACHE_FOLDER = os.path.join(os.path.expanduser('~'), ".evm_contracts")
_OPCODE_STATUS = load_opcode_status()


def download_bytecode(addr: str, name: str = "") -> str:
    url = "https://cloudflare-eth.com"
    req = {
        "id": 0,
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [addr, "latest"],
    }
    print(f"Downloading bytecode from contract address {addr}...")
    resp = requests.post(url, json=req)
    resp.raise_for_status()
    ret = json.loads(resp.text)

    if "error" in ret:
        print(ret["error"])
        raise RuntimeError(ret["error"])

    assert "result" in ret
    return ret["result"]


def get_bytecode(addr: str):
    if not os.path.isdir(_CACHE_FOLDER):
        os.mkdir(_CACHE_FOLDER)

    cache_fn = os.path.join(_CACHE_FOLDER, addr)
    if os.path.isfile(cache_fn):
        with open(cache_fn) as f:
            return f.read()

    bytecode = download_bytecode(addr)
    with open(os.path.join(_CACHE_FOLDER, addr), 'w') as f:
        f.write(bytecode)
    return bytecode


def analyze(addr: str):
    code_str = get_bytecode(addr)
    code = evmdasm.EvmBytecode(code_str).disassemble()

    opcode_name = {}
    supported_opcodes = set()
    wip_opcodes = set()

    for instr in code:
        if instr.name.startswith("UNKNOWN") or instr.name.startswith("UNOFFICIAL") or \
            instr.name.startswith("INVALID"):
            continue
        if _OPCODE_STATUS[instr.opcode] == 2:
            supported_opcodes.add(instr.name)
        else:
            wip_opcodes.add(instr.name)

    print(f"Here are the opcodes used in the contract of {addr}\n")
    print("Supported EVM opcodes:")
    print(", ".join(sorted(list(supported_opcodes))))
    print()
    print("Work-in-progress EVM opcodes:")
    print(", ".join(sorted(list(wip_opcodes))))


def main():
    parser = ArgumentParser(description="Analyze the opcodes used in a smart contract.")
    parser.add_argument("address", help="Contract address in Ethereum")
    args = parser.parse_args()

    if not args.address.startswith("0x"):
        print(f"Invalid address: {args.address}. The address should start with 0x.")
        return

    analyze(args.address)


if __name__ == "__main__":
    main()
