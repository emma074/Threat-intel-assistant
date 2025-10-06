from enrich.abuseipdb import check_ip
from rich import print
from utils.gpt_summary import summarize_threat
from discovery.input_handler import parse_arguments, collect_ips

def check_single_ip(ip):
    """Check a single IP and display results"""
    print(f"\n[bold blue]Checking IP:[/bold blue] {ip}")
    result = check_ip(ip)

    if "error" in result:
        print(f"[red]Error:[/red] {result['error']}")
    else:
        print(f"[green]Abuse Score:[/green] {result['abuseConfidenceScore']}")
        print(f"[yellow]Country:[/yellow] {result['countryCode']}")
        print(f"[cyan]ISP:[/cyan] {result['isp']}")
        print(f"[white]Last Reported At:[/white] {result['lastReportedAt']}")
        
        # Generate dynamic summary
        try:
            summary = summarize_threat(result, audience="technical", focus="risk")
            print(f"\n[bold magenta]Dynamic Analysis:[/bold magenta] {summary}")
        except Exception as e:
            print(f"[red]Analysis Failed:[/red] {e}")

def main():
    args = parse_arguments()
    
    # Collect IPs from all sources
    ips = collect_ips(args)
    
    if not ips:
        # Fallback to original file-based approach
        try:
            with open("data/iocs.txt", "r") as file:
                ips = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("[red]Error: No IPs provided and iocs.txt file not found.[/red]")
            print("[yellow]Usage examples:[/yellow]")
            print("  python main.py --ips 8.8.8.8 1.1.1.1")
            print("  python main.py --file data/new_ips.txt")
            print("  python main.py --logs /var/log/auth.log")
            print("  python main.py --network 192.168.1.0/24")
            print("  python main.py --feeds")
            return

    print(f"\n[bold green]Checking {len(ips)} IPs...[/bold green]")
    
    for ip in ips:
        check_single_ip(ip)

if __name__ == "__main__":
    main()
