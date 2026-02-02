#!/usr/bin/env python3
import sys
import argparse
import logging

from src.network_analyzer.config import load_config, get_nested
from src.network_analyzer.app import NetworkAnalyzerEngine
from src.network_analyzer.cli import NetworkAnalyzerCLI
from src.network_analyzer.history import ScanHistory


def setup_logging(config: dict) -> None:
    log_level = get_nested(config, 'logging', 'level', default='INFO')
    log_file = get_nested(config, 'logging', 'file', default=None)
    log_format = get_nested(config, 'logging', 'format',
                            default='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=log_format,
        handlers=handlers
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='wifg',
        description='Wif-G - Network Security Analysis and Optimization Tool',
    )

    parser.add_argument(
        '--scan-only',
        choices=['network', 'dns', 'ports', 'performance', 'security'],
        help='Run only a specific scan type'
    )
    parser.add_argument(
        '--export',
        choices=['json', 'html'],
        help='Export results to JSON or HTML format'
    )
    parser.add_argument(
        '--export-dir',
        default=None,
        help='Output directory for exported reports (default: ./reports)'
    )
    parser.add_argument(
        '--config',
        default=None,
        help='Path to configuration file (YAML)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose/debug output'
    )
    parser.add_argument(
        '--no-optimize',
        action='store_true',
        help='Skip optimization suggestions and prompts'
    )
    parser.add_argument(
        '--history',
        action='store_true',
        help='Show scan history'
    )
    parser.add_argument(
        '--compare',
        action='store_true',
        help='Compare current scan with previous scan'
    )
    parser.add_argument(
        '--save',
        action='store_true',
        help='Save scan results to history database'
    )

    return parser.parse_args()


def run_selective_scan(engine: NetworkAnalyzerEngine, cli: NetworkAnalyzerCLI,
                       scan_type: str) -> None:
    """Run a single scan type."""
    cli.print_banner()

    if scan_type == 'network':
        cli.print_loading("Scanning network")
        data = engine.scan_network()
        cli.print_done()
        cli.display_network(data)

    elif scan_type == 'dns':
        cli.print_loading("Analyzing DNS servers")
        data = engine.scan_dns()
        cli.print_done()
        cli.display_dns(data)

    elif scan_type == 'ports':
        engine.scan_network()  # Need gateway for port scan
        cli.print_loading("Scanning ports")
        data = engine.scan_ports()
        cli.print_done()
        cli.display_ports(data)

    elif scan_type == 'performance':
        engine.scan_network()  # Need gateway for performance tests
        cli.print_loading("Running performance tests")
        data = engine.run_performance_tests()
        cli.print_done()
        cli.display_performance(data)

    elif scan_type == 'security':
        # Security needs all scans
        run_full_scan(engine, cli, optimize=False)


def run_full_scan(engine: NetworkAnalyzerEngine, cli: NetworkAnalyzerCLI,
                  optimize: bool = True) -> None:
    """Run a full analysis."""
    cli.print_banner()

    cli.print_loading("Scanning network")
    network_data = engine.scan_network()
    cli.print_done()
    cli.display_network(network_data)

    cli.print_loading("Analyzing DNS servers")
    dns_data = engine.scan_dns()
    cli.print_done()
    cli.display_dns(dns_data)

    cli.print_loading("Running performance tests")
    perf_data = engine.run_performance_tests()
    cli.print_done()
    cli.display_performance(perf_data)

    cli.print_loading("Scanning ports")
    port_data = engine.scan_ports()
    cli.print_done()
    cli.display_ports(port_data)

    cli.print_loading("Performing security analysis")
    security_data = engine.analyze_security()
    cli.print_done()
    cli.display_security(security_data)

    if optimize:
        opt_data = engine.get_optimization_plan()
        has_optimizations = cli.display_optimization_plan(opt_data)

        if has_optimizations:
            from colorama import Fore
            print(f"\n{Fore.YELLOW}Would you like to apply optimizations? (yes/no): ", end='')
            try:
                response = input().strip().lower()
                if response in ('yes', 'y'):
                    results = engine.apply_optimizations()
                    cli.display_optimizations_applied(results)
                else:
                    print(f"\n{Fore.CYAN}Optimizations skipped. You can apply them manually.")
            except EOFError:
                pass


def main():
    args = parse_args()
    config = load_config(args.config)

    if args.verbose:
        config.setdefault('logging', {})['level'] = 'DEBUG'

    setup_logging(config)
    logger = logging.getLogger(__name__)

    try:
        # Show history
        if args.history:
            engine = NetworkAnalyzerEngine(config)
            cli = NetworkAnalyzerCLI(engine)
            history = ScanHistory()
            scans = history.list_scans()
            cli.display_history(scans)
            return

        engine = NetworkAnalyzerEngine(config)
        cli = NetworkAnalyzerCLI(engine)

        # Run scan
        if args.scan_only:
            run_selective_scan(engine, cli, args.scan_only)
        else:
            run_full_scan(engine, cli, optimize=not args.no_optimize)

        # Export if requested
        if args.export:
            filepath = engine.export_report(
                format=args.export,
                output_dir=args.export_dir
            )
            from colorama import Fore
            print(f"\n{Fore.GREEN}Report exported to: {filepath}")

        # Save to history if requested
        if args.save:
            scan_id = engine.save_to_history()
            from colorama import Fore
            print(f"\n{Fore.GREEN}Scan saved to history (ID: {scan_id})")

        # Show comparison if requested
        if args.compare:
            history = ScanHistory()
            comparison = history.get_comparison()
            if comparison:
                cli.display_comparison(comparison)

        from colorama import Fore
        print(f"\n{Fore.GREEN}Analysis complete!")
        print(f"{Fore.CYAN}{'=' * 60}\n")

    except KeyboardInterrupt:
        from colorama import Fore
        print(f"\n\n{Fore.YELLOW}Program interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Error during analysis")
        from colorama import Fore
        print(f"\n{Fore.RED}Error occurred: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
