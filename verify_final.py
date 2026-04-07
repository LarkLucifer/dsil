"""
Final verification script for DSIL imports and dead code.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).parent / "dsil"
ENTRYPOINTS = {"dsil.cli", "dsil.core.pipeline"}


def list_modules() -> dict[str, Path]:
    modules: dict[str, Path] = {}
    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT)
        parts = rel.with_suffix("").parts
        mod = ".".join(("dsil",) + parts)
        modules[mod] = path
    return modules


def parse_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("dsil"):
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("dsil"):
                imports.add(node.module)
    return imports


def build_graph(modules: dict[str, Path]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {m: set() for m in modules}
    for mod, path in modules.items():
        imports = parse_imports(path)
        for imp in imports:
            if imp in modules:
                graph[mod].add(imp)
    return graph


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(node: str, stack: list[str]) -> None:
        if node in visiting:
            cycle = stack[stack.index(node) :]
            cycles.append(cycle)
            return
        if node in visited:
            return
        visiting.add(node)
        stack.append(node)
        for nxt in graph[node]:
            dfs(nxt, stack)
        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for n in graph:
        if n not in visited:
            dfs(n, [])

    return cycles


def reachable(graph: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()

    def walk(node: str) -> None:
        if node in seen:
            return
        seen.add(node)
        for nxt in graph.get(node, set()):
            walk(nxt)

    for entry in ENTRYPOINTS:
        if entry in graph:
            walk(entry)

    return seen


def main() -> int:
    modules = list_modules()
    graph = build_graph(modules)

    cycles = find_cycles(graph)
    if cycles:
        print("Circular imports detected:")
        for c in cycles:
            print("  - " + " -> ".join(c))
    else:
        print("No circular imports detected.")

    live = reachable(graph)
    dead = sorted(set(modules) - live)

    if dead:
        print("Potential dead modules (not reachable from entrypoints):")
        for d in dead:
            print("  - " + d)
    else:
        print("No dead modules detected.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
