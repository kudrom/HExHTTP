"""Core modules for HExHTTP vulnerability detection."""
from utils.style import Colors

# cp & cpdos
from modules.cachepoisoning.cache_poisoning_nf_files import check_cache_files
from modules.cachepoisoning.cache_poisoning import check_cache_poisoning
from modules.cpdos.fmp import check_methods_poisoning
from modules.CPDoS import check_CPDoS
from modules.CVE import check_cpcve
from modules.header_checks.cachetag_header import check_cachetag_header

# header checks
from modules.header_checks.check_localhost import check_localhost
from modules.header_checks.http_version import check_http_version
from modules.header_checks.methods import check_methods
from modules.header_checks.server_error import check_server_error
from modules.header_checks.uncommon_header import check_http_headers
from modules.header_checks.vhosts import check_vhost
from modules.header_checks.debug_header import check_http_debug

from utils.utils import configure_logger, check_waf

logger = configure_logger('modules')

def get_modules():
    return {
        name: func 
        for name, func in globals().items()
        if name.startswith("check_") and callable(func)
    }

def run_module(module, kwargs):
    modules = get_modules()
    if module not in modules:
        logger.error(f'{module} not in modules')
    else:
        print(f"{Colors.CYAN} ├ Running {module} {Colors.RESET}")
        modules[module](**kwargs)