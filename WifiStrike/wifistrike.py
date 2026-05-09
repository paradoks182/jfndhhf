import os
import sys
import time
import ast
import threading
import importlib.util
from colorama import init, Fore, Back, Style
init()

RED = '\033[91m'
WHITE = '\033[97m'
RESET = '\033[0m'
BOLD = '\033[1m'

VERSION = "v0.1"

def red(text):
    return RED + BOLD + str(text) + RESET

def white(text):
    return WHITE + str(text) + RESET

def err(msg="ERROR"):
    return f"{RED}[!]{RESET} {msg}"

def info(msg="INFO"):
    return f"{WHITE}[*]{RESET} {msg}"

def ok(msg="OK"):
    return f"{RED}[+]{RESET} {msg}"

BANNER = white("""
 __          ___  __ _  _____ _        _ _
 \\ \\        / (_)/ _(_)/ ____| |      (_) |
  \\ \\  /\\  / / _| |_ _| (___ | |_ _ __ _| | _____
   \\ \\/  \\/ / | |  _| |\\___ \\| __| '__| | |/ / _ \\
    \\  /\\  /  | | | | |____) | |_| |  | |   <  __/
     \\/  \\/   |_|_| |_|_____/ \\__|_|  |_|_|\\_\\___|

""")

TITLE = f"{Fore.WHITE}{Back.RED}WifiStrikeFrameWork{Style.RESET_ALL}"

CATEGORIES = ["wifi", "router", "cameras", "iot", "network", "protocols", "cve", "scanner", "encoders", "payloads", "post"]

animdone = threading.Event()
stopanim = threading.Event()

def animation():
    try:
        frames = ["|", "/", "-", "\\"]
        for i in range(20):
            for frame in frames:
                if stopanim.is_set():
                    break
                sys.stdout.write(f"\r{info('Initializing WiFiStrike')} {frame}")
                sys.stdout.flush()
                time.sleep(0.1)
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()
    finally:
        animdone.set()

def check():
    counts = {}
    for cat in CATEGORIES:
        counts[cat] = 0

    errlog = []

    threading.Thread(target=animation, daemon=True).start()

    if not os.path.exists("Modules"):
        os.makedirs("Modules", exist_ok=True)
        for cat in CATEGORIES:
            os.makedirs(os.path.join("Modules", cat), exist_ok=True)
            open(os.path.join("Modules", cat, "__init__.py"), 'a').close()
        open(os.path.join("Modules", "__init__.py"), 'a').close()

    for cat in CATEGORIES:
        path = os.path.join("Modules", cat)
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            open(os.path.join(path, "__init__.py"), 'a').close()

    for root, dirs, files in os.walk("Modules"):
        for file in files:
            if file.endswith(".py") and file != "__init__.py":
                for cat in CATEGORIES:
                    if f"{os.sep}{cat}" in root:
                        counts[cat] += 1

                modul = os.path.join(root, file)
                try:
                    with open(modul, "r", encoding="utf-8") as f:
                        code = f.read()
                        ast.parse(code)
                except SyntaxError as e:
                    errlog.append(f"Syntax error in {file}: {e}")
                except:
                    pass

    if errlog:
        stopanim.set()
        print()
        for r in errlog:
            print(err(r))
        print()

    animdone.wait()
    mainmenu(counts)

def mainmenu(counts):
    print(BANNER)
    print(TITLE)
    print()

    total_modules = sum(counts.values())

    wifi_count = counts.get("wifi", 0)
    router_count = counts.get("router", 0)
    cameras_count = counts.get("cameras", 0)
    iot_count = counts.get("iot", 0)
    network_count = counts.get("network", 0)
    protocols_count = counts.get("protocols", 0)
    cve_count = counts.get("cve", 0)
    scanner_count = counts.get("scanner", 0)
    encoders_count = counts.get("encoders", 0)
    payloads_count = counts.get("payloads", 0)
    post_count = counts.get("post", 0)

    exploits_total = router_count + cameras_count + iot_count + network_count + protocols_count
    attacks_total = wifi_count
    extra_total = encoders_count + payloads_count + post_count

    modules_info = f"{total_modules} total"
    exploits_info = f"{exploits_total} exploits" if exploits_total > 0 else ""
    wifi_info = f"{wifi_count} wifi" if wifi_count > 0 else ""
    cve_info = f"{cve_count} cve" if cve_count > 0 else ""
    scanner_info = f"{scanner_count} scanner" if scanner_count > 0 else ""
    post_info = f"{post_count} post" if post_count > 0 else ""
    payloads_info = f"{payloads_count} payloads" if payloads_count > 0 else ""
    encoders_info = f"{encoders_count} encoders" if encoders_count > 0 else ""

    info_parts = []
    if wifi_info: info_parts.append(wifi_info)
    if exploits_info: info_parts.append(exploits_info)
    if cve_info: info_parts.append(cve_info)
    if scanner_info: info_parts.append(scanner_info)
    if post_info: info_parts.append(post_info)
    if payloads_info: info_parts.append(payloads_info)
    if encoders_info: info_parts.append(encoders_info)

    info_str = " - ".join(info_parts) if info_parts else "no modules"

    print(white(f"+- --=[ {VERSION} ]-"))
    print(white(f"+- --=[ {info_str} ]-"))
    print()

    WifiStrike(counts)

class WifiStrike:
    def __init__(self, counts):
        self.counts = counts
        self.options = {}
        self.selectmod = ""
        self.categories = CATEGORIES
        self.modules = []
        self.global_target = ""
        self.load_modules()
        self.run()

    def parse(self, args):
        if not args:
            return {}
        params = {}
        for i in args:
            if ":" in i:
                key, value = i.split(":", 1)
                params[key.lower()] = value
        return params

    def get_meta(self, path, meta):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            for line in content.split("\n"):
                if line.strip().startswith(f"{meta.upper()} ="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
            return "Unknown"
        except:
            return "Unknown"

    def load_modules(self):
        for folder in self.categories:
            path = os.path.join("Modules", folder)
            if os.path.exists(path):
                for file in os.listdir(path):
                    if file.endswith(".py") and file != "__init__.py":
                        modulepath = os.path.join(path, file)
                        self.modules.append({
                            "name": file.replace(".py", ""),
                            "type": folder,
                            "description": self.get_meta(modulepath, "DESCRIPTION"),
                            "date": self.get_meta(modulepath, "DATE"),
                            "rank": self.get_meta(modulepath, "RANK"),
                            "author": self.get_meta(modulepath, "AUTHOR")
                        })

    def table(self, modtype=None):
        if modtype:
            if modtype not in self.categories:
                print(err(f"Unknown category: {modtype}"))
                print(info(f"Available: {', '.join(self.categories)}"))
                return
            filtered = [m for m in self.modules if m["type"] == modtype]
        else:
            filtered = self.modules

        if not filtered:
            print(err("No modules found"))
            return

        print()
        print(info(f"Found {len(filtered)} modules"))
        print("=" * 70)
        print(f" {'#':<3} {'Module':<35} {'Category':<12} {'Rank':<10}")
        print("-" * 70)

        for i, mod in enumerate(filtered):
            name = mod['name']
            if len(name) > 33:
                name = name[:30] + "..."
            print(f" {i:<3} {name:<35} {mod['type']:<12} {mod['rank']:<10}")

        print()

    def categories_list(self):
        print()
        print(info("Available categories:"))
        print("-" * 40)
        for cat in self.categories:
            cnt = self.counts.get(cat, 0)
            modules_list = [m for m in self.modules if m["type"] == cat]
            print(f"  {cat:<15} ({cnt} modules)")
            if modules_list:
                for m in modules_list:
                    print(f"    - {m['name']}")
        print()

    def clear(self):
        os.system("clear" if os.name != "nt" else "cls")
        mainmenu(self.counts)

    def show_status(self):
        print()
        print(white("─" * 40))
        print(white(f"  Global Target: {self.global_target if self.global_target else 'Not set'}"))
        print(white(f"  Selected Module: {self.selectmod if self.selectmod else 'None'}"))

        if self.options:
            print(white(f"  Module Options:"))
            for k, v in self.options.items():
                print(white(f"    {k}: {v}"))

        print(white("─" * 40))
        print()

    def run(self):
        while True:
            try:
                mod_display = f" {red('(' + self.selectmod + ')')}" if self.selectmod else ""
                rawcmd = input(f"{white('wifistrike')}{mod_display} > ").strip()

                if not rawcmd:
                    continue

                parts = rawcmd.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []

                if cmd in ["exit", "quit"]:
                    print(info("Goodbye!"))
                    sys.exit(0)

                elif cmd == "help":
                    print(f"""
{red('WiFiStrike Commands:')}
{red('─' * 40)}
{white('Core Commands:')}
  target <ip/host>        Set global target for all modules
  target                  Show current global target
  status                  Show global target and current module info
  help                    Show this menu
  clear                   Clear screen
  exit                    Exit

{white('Module Commands:')}
  categories              Show all categories and modules
  search <category>       Search modules by category
  search all              Show all modules
  use <category>/<module> Select module
  options                 Show module options
  set <key>:<value>       Set parameter
  run                     Execute module
  back                    Deselect module


{red('Categories:')}
  {', '.join(self.categories)}
                    """)

                elif cmd == "target":
                    if args:
                        self.global_target = args[0]
                        self.options["target"] = args[0]
                        print(ok(f"Global target set to: {self.global_target}"))
                        print(info("This target will be used by all modules unless overridden"))
                    else:
                        if self.global_target:
                            print(info(f"Global target: {self.global_target}"))
                        else:
                            print(err("No global target set"))
                            print(info("Usage: target <ip/host>"))

                elif cmd == "status":
                    self.show_status()

                elif cmd == "categories":
                    self.categories_list()

                elif cmd == "search":
                    if not args or args[0] == "all":
                        self.table(None)
                    else:
                        self.table(args[0])

                elif cmd == "use":
                    if not args:
                        print(err("Usage: use <category>/<module>"))
                        continue

                    module = args[0]

                    if "/" not in module:
                        print(err("Format: category/module_name"))
                        continue

                    cat, modname = module.split("/", 1)

                    if cat not in self.categories:
                        print(err(f"Unknown category: {cat}"))
                        print(info(f"Available: {', '.join(self.categories)}"))
                        continue

                    found = False

                    for m in self.modules:
                        mpath = f"{m['type']}/{m['name']}"
                        if module.lower() == mpath.lower():
                            found = True
                            self.selectmod = mpath
                            self.options = {}

                            if self.global_target:
                                self.options["target"] = self.global_target

                            print(ok(f"Loaded: {mpath}"))
                            print(info(f"Description: {m['description']}"))
                            print(info(f"Author: {m['author']}"))
                            print(info(f"Rank: {m['rank']}"))

                            if self.global_target:
                                print(info(f"Target auto-set: {self.global_target}"))

                            mtype, mname = self.selectmod.split("/")
                            modpath = os.path.join("Modules", mtype, mname + ".py")

                            try:
                                spec = importlib.util.spec_from_file_location(mname, modpath)
                                mod = importlib.util.module_from_spec(spec)
                                spec.loader.exec_module(mod)

                                if hasattr(mod, "OPTIONS"):
                                    for k, v in mod.OPTIONS.items():
                                        if k == "target" and self.global_target:
                                            self.options[k] = self.global_target
                                        else:
                                            self.options[k] = v["default"]
                                        print(info(f"  {k}: {self.options[k]} ({v['description']})"))
                            except Exception as e:
                                print(err(f"Cannot load module: {e}"))

                    if not found:
                        print(err(f"Module not found: {module}"))

                elif cmd == "options":
                    if not self.selectmod:
                        print(err("No module selected"))
                        continue

                    mtype, mname = self.selectmod.split("/")
                    modpath = os.path.join("Modules", mtype, mname + ".py")

                    try:
                        spec = importlib.util.spec_from_file_location(mname, modpath)
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)

                        if hasattr(mod, "OPTIONS"):
                            print(f"\n{info('Module options:')}\n")
                            print(f" {'Option':<15} {'Value':<20} {'Description'}")
                            print("-" * 50)
                            for k, v in mod.OPTIONS.items():
                                current = self.options.get(k, v["default"])
                                if self.global_target and k == "target":
                                    current = self.global_target
                                print(f" {k:<15} {str(current):<20} {v['description']}")
                            print()
                    except Exception as e:
                        print(err(str(e)))

                elif cmd == "set":
                    if not args:
                        print(err("Usage: set <key>:<value>"))
                        continue

                    params = self.parse(args)
                    for k, v in params.items():
                        self.options[k] = v
                        if k == "target":
                            self.global_target = v
                            print(ok(f"Global target updated: {v}"))
                        else:
                            print(ok(f"{k} => {v}"))

                elif cmd == "run":
                    if not self.selectmod:
                        print(err("No module selected"))
                        continue

                    if "target" not in self.options or not self.options["target"]:
                        if self.global_target:
                            self.options["target"] = self.global_target
                            print(info(f"Using global target: {self.global_target}"))
                        else:
                            print(err("No target specified!"))
                            print(info("Set with: target <ip> OR set target:<ip>"))
                            continue

                    mtype, mname = self.selectmod.split("/")
                    modpath = os.path.join("Modules", mtype, mname + ".py")

                    if not os.path.exists(modpath):
                        print(err(f"Module file not found: {modpath}"))
                        continue

                    try:
                        spec = importlib.util.spec_from_file_location(mname, modpath)
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)

                        if hasattr(mod, "run"):
                            print(info(f"Executing {self.selectmod}..."))
                            print(info(f"Target: {self.options.get('target', 'N/A')}"))
                            print()
                            mod.run(self.options)
                        else:
                            print(err("Module has no run() function"))
                    except Exception as e:
                        print(err(str(e)))

                elif cmd == "back":
                    self.selectmod = ""
                    self.options = {}
                    print(info("Module deselected"))

                elif cmd == "clear":
                    self.clear()

                else:
                    print(err(f"Unknown command: {cmd}"))

            except KeyboardInterrupt:
                print()
                choice = input(info("Exit? (y/n) > ")).lower()
                if choice == "y":
                    print(info("Goodbye!"))
                    sys.exit(0)
                else:
                    mainmenu(self.counts)

            except Exception as e:
                print(err(str(e)))

if __name__ == "__main__":
    check()
