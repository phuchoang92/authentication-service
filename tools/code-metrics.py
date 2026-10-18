#!/usr/bin/env python3
"""Đo các luật trong CLAUDE.md. Chạy từ thư mục authentication-service:

    python3 tools/code-metrics.py            # mọi mục
    python3 tools/code-metrics.py trace      # chỉ một mục: trace | ports | exceptions | records | dead

Chỉ đọc src/main. Không sửa gì.
"""
import os
import re
import sys
from collections import Counter

ROOT = os.path.join(os.path.dirname(__file__), "..", "src", "main", "java", "com", "vpbank", "dcp")
ENTRY_POINTS = ["PasswordLoginController", "TrustedDeviceController"]

files = {}
for directory, _, names in os.walk(ROOT):
    for name in names:
        if name.endswith(".java"):
            files[name[:-5]] = os.path.relpath(os.path.join(directory, name), ROOT)


def source(name):
    text = open(os.path.join(ROOT, files[name])).read()
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)


code = {name: source(name) for name in files}
implementers = {}
for name, text in code.items():
    declared = re.search(r"\bimplements\s+([\w\s,<>.]+?)\s*\{", text)
    if declared:
        for interface in re.findall(r"[A-Z]\w+", declared.group(1)):
            implementers.setdefault(interface, set()).add(name)


def references(name):
    found = {word for word in re.findall(r"\b[A-Z]\w+\b", code[name]) if word in files and word != name}
    return found | implementers.get(name, set())


def is_config(name):
    return files[name].startswith("infrastructure/config/")


def trace():
    print("== trace: số kiểu phải mở từ controller (tính cả implementation), không tính config")
    for entry in ENTRY_POINTS:
        if entry not in files:
            continue
        seen, todo = {entry}, [entry]
        while todo:
            for other in references(todo.pop()):
                if other not in seen and not is_config(other):
                    seen.add(other)
                    todo.append(other)
        lines = sum(len(open(os.path.join(ROOT, files[n])).read().splitlines()) for n in seen)
        tiny = sum(len(open(os.path.join(ROOT, files[n])).read().splitlines()) <= 15 for n in seen)
        print(f"  {entry}: {len(seen)} kiểu, {lines} dòng, {tiny} file <=15 dòng")


def ports():
    print("== ports: interface mà mọi implementation đều nằm trong core (không phải biên thật)")
    for name, text in sorted(code.items()):
        if not re.search(r"\bpublic\s+interface\s+" + name + r"\b", text) or "org.springframework.data" in text:
            continue  # Spring Data generates JPA repository implementations
        impls = implementers.get(name, set())
        if not impls:
            print(f"  0 impl   {files[name]}")
        elif all(files[i].startswith("core/") for i in impls):
            print(f"  {len(impls)} impl core  {files[name]}")


def exceptions():
    print("== exceptions: class exception không có catch/@ExceptionHandler nào phân biệt")
    for name in sorted(n for n in files if n.endswith("Exception")):
        caught = any(re.search(r"catch\s*\([^)]*\b" + name + r"\b", t) or
                     re.search(r"ExceptionHandler\([^)]*\b" + name + r"\b", t)
                     for other, t in code.items() if other != name)
        if not caught:
            print(f"  {files[name]}")


def records():
    print("== records trong core: >6 thành phần, hoặc 2 boolean liền nhau")
    for name, text in sorted(code.items()):
        if not files[name].startswith("core/"):
            continue
        for match in re.finditer(r"\brecord\s+(\w+)\s*\(([^)]*)\)", text, re.S):
            components = [c for c in re.split(r",(?![^<]*>)", match.group(2)) if c.strip()]
            types = [re.sub(r"@\w+(\([^)]*\))?", "", c).split()[0] for c in components]
            twins = any(types[i] == types[i + 1] == "boolean" for i in range(len(types) - 1))
            if len(components) > 6 or twins:
                note = " (boolean liền nhau)" if twins else ""
                print(f"  {len(components)} thành phần{note}  {match.group(1)}  {files[name]}")


def dead():
    print("== dead: kiểu không được kiểu nào khác trong src/main nhắc tên (test không tính)")
    used = Counter()
    for name, text in code.items():
        for word in set(re.findall(r"\b[A-Z]\w+\b", text)):
            if word in files and word != name:
                used[word] += 1
    for name in sorted(files):
        if used[name] == 0 and not name.endswith("Application") and "@RestController" not in code[name] \
                and "@Configuration" not in code[name] and "@ControllerAdvice" not in code[name] \
                and "@RestControllerAdvice" not in code[name] and "@Repository" not in code[name]:
            print(f"  {files[name]}")


def overview():
    sizes = [len(open(os.path.join(ROOT, p)).read().splitlines()) for p in files.values()]
    print(f"== tổng: {len(files)} file, {sum(sizes)} dòng, {sum(s <= 15 for s in sizes)} file <=15 dòng")


SECTIONS = {"trace": trace, "ports": ports, "exceptions": exceptions, "records": records, "dead": dead}
selected = sys.argv[1:] or ["overview", *SECTIONS]
for section in selected:
    (overview if section == "overview" else SECTIONS[section])()
