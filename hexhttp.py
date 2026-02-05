#!/usr/bin/env python3
import argparse

from datetime import datetime
from queue import Empty, Queue
from threading import Thread

# utils
import utils.proxy as proxy
from cli import get_args

from modules import run_module

# others
from modules.Technology import Technology
from utils.style import Colors
from utils.utils import (
    check_auth,
    configure_logger,
    get_domain_from_url,
    requests,
    sys,
    time,
    configure_logging
)

logger = configure_logger(__name__)

# Global queue for multi-threaded processing
enclosure_queue: Queue[str] = Queue()


def get_technos(
    url: str, s: requests.Session, req_main: requests.Response, a_tech: Technology
) -> None:
    """
    Check what is the reverse proxy/WAF/cached server... and test based on the result.
    #TODO Cloudfoundry => https://hackerone.com/reports/728664
    """
    print(f"{Colors.CYAN} ├ Techno analysis{Colors.RESET}")
    technos = {
        "apache": ["apache", "tomcat"],
        "nginx": ["nginx"],
        "envoy": ["envoy"],
        "akamai": [
            "akamai",
            "x-akamai",
            "x-akamai-transformed",
            "akamaighost",
            "akamaiedge",
            "edgesuite",
        ],
        "imperva": ["imperva"],
        "fastly": ["fastly"],
        "cloudflare": ["cf-ray", "cloudflare", "cf-cache-status", "cf-ray"],
        "cloudfront": ["x-amz-cf", "cloudfront", "x-amz-request-id"],
        "vercel": ["vercel"],
        # "cloudfoundry": ["cf-app"]
    }

    technologies_detected = False
    for t in technos:
        tech_hit: str | bool = False
        for v in technos[t]:
            for rt in req_main.headers:
                # case-insensitive comparison
                if (
                    v.lower() in req_main.text.lower()
                    or v.lower() in req_main.headers[rt].lower()
                    or v.lower() in rt.lower()
                ):
                    tech_hit = t
                    break  # Exit inner loops once we find a match
            if tech_hit:
                break
        if tech_hit and isinstance(tech_hit, str):
            getattr(a_tech, tech_hit)(url, s)
            technologies_detected = True
            tech_hit = False

    if not technologies_detected:
        print(
            f"{Colors.YELLOW} │ └── No specific technologies detected{Colors.RESET}"
        )


def process_modules(url: str, s: requests.Session, args: argparse.Namespace) -> None:
    domain = get_domain_from_url(url)
    authent = check_auth(args.auth, url)
    a_tech = Technology()
    resp_main_headers = []

    try:
        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=authent
        )

        main_status_code = req_main.status_code
        main_len = len(req_main.content)

        print(f"{Colors.BLUE}⟙{Colors.RESET}")
        # print(s.headers)
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.SALMON}[STARTED]{Colors.RESET} {start_time}")
        print(f" Modules: {', '.join(args.modules)}")
        print(f" URL: {url}")
        print(f" URL response: {Colors.GREEN}{main_status_code}{Colors.RESET}") if main_status_code == 200 else print(f" URL response: {Colors.YELLOW}{main_status_code}{Colors.RESET}")
        print(f" URL response size: {main_len} bytes")
        proxy_status = f" Proxy: {Colors.RED}OFF{Colors.RESET}"
        if proxy.proxy_enabled:
            proxy_status = f" Proxy: {Colors.GREEN}ON{Colors.RESET} ({proxy.proxy_url})"
        if proxy.burp_enabled:
            proxy_status += f" | Burp: {Colors.GREEN}ON{Colors.RESET} ({proxy.burp_url})"
        print(proxy_status)
        print(f"{Colors.BLUE}⟘{Colors.RESET}")
        print(f"{Colors.BLUE}⟙{Colors.RESET}")

        if main_status_code not in [200, 302, 301, 403, 401] and not args.url_file and not args.force:
            choice = input(
                f" {Colors.YELLOW}The url does not seem to answer correctly, continue anyway ?{Colors.RESET} [y/n]"
            )
            if choice not in ["y", "Y"]:
                sys.exit()
        for k in req_main.headers:
            resp_main_headers.append(f"{k}: {req_main.headers[k]}")
        
        kwargs = {
            'url': url,
            'args': args,
            'authent': authent,
            'req': req_main,
            'resp_main_headers': resp_main_headers,
            'domain': domain,
            's': s
        }

        get_technos(url, s, req_main, a_tech)
        for module in args.modules:
            run_module(module, kwargs)

    # requests errors
    except requests.ConnectionError as e:
        if "Connection refused" in str(e):
            print(f"Error, connection refused by target host: {e}")
        else:
            print(f"Error, cannot connect to target: {e}")
    except requests.Timeout:
        print("Error, request timeout (10s)")
    except requests.exceptions.MissingSchema:
        print("Error, missing http:// or https:// schema")


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def main(urli: str, s: requests.Session, args: argparse.Namespace | None) -> None:
    if args.url_file and args.threads != 1337:
        try:
            while True:
                try:
                    if isinstance(urli, Queue):
                        url = urli.get_nowait()
                    else:
                        url = urli
                        # For single URL, break after processing
                        process_modules(url, s, args)
                        break
                except Empty:
                    break
                try:
                    process_modules(url, s, a_tech)
                except Exception:
                    logger.exception(f"Error processing URL {url}")
                finally:
                    if isinstance(urli, Queue):
                        urli.task_done()
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(f"Worker thread error: {e}")
            logger.exception(e)
    else:
        try:
            process_modules(urli, s, args)
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()


def cli_main() -> None:
    """Entry point for the CLI command."""
    # Parse arguments
    args = get_args()
    configure_logging(args.verbose, args.log, args.log_file)      

    try:
        s = requests.Session()
        s.verify = False
        s.max_redirects = 60
        s.headers.update(
            {
                "User-Agent": f"{args.user_agent}-BugBounty",
                #DECOMMENTHIS
                #"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                #"Accept-Language": "en-US,en;q=0.5",
                #"Accept-Encoding": "gzip, deflate, br",
                #"Connection": "keep-alive",
                #"Upgrade-Insecure-Requests": "1",
                #"Sec-Fetch-Dest": "document",
                #"Sec-Fetch-Mode": "navigate",
                #"Sec-Fetch-Site": "none",
                #"Sec-Fetch-User": "?1",
                #"Priority": "u=4",
            }
        )

        if args.custom_header:
            try:
                custom_headers = parse_headers(args.custom_header)
                s.headers.update(custom_headers)
            except Exception as e:
                logger.exception(e)
                print(f" Error in custom header format: {e}")
                sys.exit()

        # Handle proxy configuration
        if args.proxy is not None or args.burp is not None:
            # Configure main proxy
            if args.proxy is not None:  # Handle both empty string (default) and provided value
                proxy.proxy_url = proxy.parse_proxy_url(args.proxy)
                test_proxy = proxy.test_proxy_connection(proxy.proxy_url)
                if test_proxy:
                    proxy.proxy_enabled = True
                    print(f" Proxy configured: {proxy.proxy_url}")
                else:
                    # For regular proxy, just warn but continue (some proxies might not allow httpbin.org)
                    print(f" {Colors.YELLOW}Proxy connection test failed, but continuing: {proxy.proxy_url}{Colors.RESET}")
                    proxy.proxy_enabled = True
            
            # Configure Burp proxy
            if args.burp is not None:  # Handle both empty string (default) and provided value
                proxy.burp_url = proxy.parse_proxy_url(args.burp)
                test_burp = proxy.test_proxy_connection(proxy.burp_url)
                if test_burp:
                    proxy.burp_enabled = True
                    print(f" Burp proxy configured: {proxy.burp_url}")
                else:
                    print(f" {Colors.RED}Burp proxy connection failed: {proxy.burp_url}{Colors.RESET}")
                    sys.exit(1)
            
            # If only burp is specified, also enable general proxying through burp
            if args.burp is not None and args.proxy is None:
                proxy.proxy_enabled = True
                proxy.proxy_url = proxy.burp_url
            
            s.proxies = {"http": proxy.proxy_url, "https": proxy.proxy_url}

        if args.url_file and args.threads != 1337:
            with open(args.url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
            try:
                for url in urls:
                    enclosure_queue.put(url)
                worker_threads = []
                for _ in range(args.threads or 1):
                    worker = Thread(target=main, args=(enclosure_queue, s, args))
                    worker.daemon = True
                    worker.start()
                    worker_threads.append(worker)
                
                enclosure_queue.join()
                
                for worker in worker_threads:
                    worker.join(timeout=60)

            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except FileNotFoundError:
                print("Input file not found")
                sys.exit()
            print("Scan finish")
        elif args.url_file and args.threads == 1337:
            with open(args.url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
                for url in urls:
                    main(url, s, args)
        else:
            main(args.url, s, args)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    print("")


if __name__ == "__main__":
    cli_main()
