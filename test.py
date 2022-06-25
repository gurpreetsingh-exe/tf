#!/usr/bin/python

import os
import pathlib
import subprocess

proj_dir = pathlib.Path(__file__).parent
test_dir = os.path.join(proj_dir, "tests")
logs_file = os.path.join(proj_dir, "tests.log")

state = lambda: None

try:
    with open(logs_file, "w") as fd:
        pass
except FileNotFoundError:
    with open(logs_file, "x") as fd:
        pass

def test_nasm_backend():
    state.passed_tests = 0
    state.failed_tests = 0
    state.compile_fail = 0

    print("INFO: Testing nasm backend")
    for path in pathlib.Path(test_dir).iterdir():
        if path.suffix != ".tf" or path.stem.startswith("mod_"):
            continue
        file_path = str(path.absolute())
        file_name = path.name
        print(f"INFO: Testing {file_name}")

        print(f"INFO: Compiling {file_path}")
        exec_name = file_name.split(".")[0]
        proc = subprocess.Popen(["./src/bootstrap/tf.py", "-c", file_path, "-be", "nasm"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = "".join([i.decode('utf-8') for i in proc.stdout.readlines()])
        proc.communicate()
        if proc.returncode != 0:
            state.compile_fail += 1
            print("ERROR: Compilation failed")
            with open(logs_file, "a") as fd:
                fd.write(f"== ERROR: compilation failed for {file_path}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
            continue

        target = os.path.join(test_dir, exec_name)
        print(f"INFO: Running {target}")
        proc = subprocess.Popen([target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = "".join([i.decode('utf-8') for i in proc.stdout.readlines()])
        proc.communicate()
        if proc.returncode != 0:
            state.failed_tests += 1
            print("ERROR: Execution failed")
            with open(logs_file, "a") as fd:
                fd.write(f"== ERROR: execution failed for {target}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
        else:
            state.passed_tests += 1
            with open(logs_file, "a") as fd:
                if proc.returncode == 101:
                    fd.write(f"[THREAD PANIC]\n")
                fd.write(f"== INFO: Output for {target}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
        subprocess.call(["rm", target, target + ".asm", target + ".o"])

    print(f"\n    passed tests:    {state.passed_tests}\t")
    print(f"    failed tests:    {state.failed_tests}\t")
    print(f"    compile fail:    {state.compile_fail}\t\n")


def test_native_backend():
    state.passed_tests = 0
    state.failed_tests = 0
    state.compile_fail = 0

    print("INFO: Testing native backend")
    for path in pathlib.Path(test_dir).iterdir():
        if path.suffix != ".tf" or path.stem.startswith("mod_"):
            continue
        file_path = str(path.absolute())
        file_name = path.name
        print(f"INFO: Testing {file_name}")

        print(f"INFO: Compiling {file_path}")
        exec_name = file_name.split(".")[0]
        proc = subprocess.Popen(["./src/bootstrap/tf.py", "-c", file_path, "-be", "native"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = "".join([i.decode('utf-8') for i in proc.stdout.readlines()])
        proc.communicate()
        if proc.returncode != 0:
            state.compile_fail += 1
            print("ERROR: Compilation failed")
            with open(logs_file, "a") as fd:
                fd.write(f"== ERROR: compilation failed for {file_path}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
            continue

        target = os.path.join(test_dir, exec_name)
        print(f"INFO: Running {target}")
        proc = subprocess.Popen([target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = "".join([i.decode('utf-8') for i in proc.stdout.readlines()])
        proc.communicate()
        if proc.returncode != 0:
            state.failed_tests += 1
            print("ERROR: Execution failed")
            with open(logs_file, "a") as fd:
                fd.write(f"== ERROR: execution failed for {target}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
        else:
            state.passed_tests += 1
            with open(logs_file, "a") as fd:
                if proc.returncode == 101:
                    fd.write(f"[THREAD PANIC]\n")
                fd.write(f"== INFO: Output for {target}\n== ")
                fd.write(lines)
                fd.write(f"== INFO: Return code: {proc.returncode}\n\n")
        subprocess.call(["rm", target])

    print(f"\n    passed tests:    {state.passed_tests}\t")
    print(f"    failed tests:    {state.failed_tests}\t")
    print(f"    compile fail:    {state.compile_fail}\t\n")

if __name__ == "__main__":
    test_nasm_backend()
    test_native_backend()
