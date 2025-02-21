import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import ipaddress
from urllib.parse import urlparse, parse_qs


def is_google_ip(ip):
    """Verify if IP belongs to Google's crawler network (IPv4 and IPv6)"""
    try:
        google_ranges = [
            "66.249.64.0/19", "66.249.80.0/20", "64.233.160.0/19", "216.239.32.0/19",
            "2001:4860:4801::/48", "2404:6800:4003::/48", "2607:f8b0:4003::/48", "2800:3f0:4003::/48"
        ]
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(net) for net in google_ranges)
    except:
        return False


def identify_search_engine(user_agent):
    """Identify search engine based on user agent"""
    search_engines = {
        'Google': ['Googlebot', 'AdsBot-Google', 'APIs-Google', 'Google-Read-Aloud', 'FeedFetcher-Google', 'Google-Site-Verification'],
        'Bing': ['bingbot']
    }
    for engine, patterns in search_engines.items():
        if any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in patterns):
            return engine
    return 'Other'


def analyze_logs(log_files):
    try:
        print("\n🔍 Analyzing search engine crawl patterns...")
        records = []
        total_lines = 0

        for log_file in log_files:
            print(f"\n📂 Processing {log_file}...")
            with open(log_file, 'r') as f:
                for line in f:
                    total_lines += 1
                    pattern = r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+).*?\[(.*?)\].*?"(\w+) (.*?) HTTP.*?" (\d+) .*?"(.*?)" "(.*?)"'
                    match = re.search(pattern, line)
                    if match:
                        ip, datetime, method, url, status, referer, user_agent = match.groups()
                        if is_google_ip(ip) or identify_search_engine(user_agent) in ['Google', 'Bing']:
                            search_engine = identify_search_engine(user_agent)
                            records.append({
                                'ip': ip, 'datetime': datetime, 'method': method,
                                'url': url, 'status': int(status), 'referer': referer,
                                'user_agent': user_agent, 'search_engine': search_engine
                            })

        df = pd.DataFrame(records)
        if df.empty:
            print("\n⚠️ No valid log entries found!")
            return None

        df['datetime'] = pd.to_datetime(
            df['datetime'], format="%d/%b/%Y:%H:%M:%S", errors='coerce')
        df = df.sort_values(by="datetime", ascending=False)

        for engine in ['Google', 'Bing']:
            print(f"\n📊 Status Code Distribution for {engine}:")
            engine_df = df[df['search_engine'] == engine]
            status_counts = engine_df['status'].value_counts()
            print(status_counts)

            plt.figure(figsize=(8, 5))
            sns.barplot(x=status_counts.index,
                        y=status_counts.values, palette='viridis')
            plt.title(f"Status Code Distribution - {engine}")
            plt.xlabel("Status Code")
            plt.ylabel("Count")
            plt.savefig(f"status_code_distribution_{engine}.png")
            plt.close()

        return df

    except MemoryError:
        print("\n🚨 Error: Memory usage exceeded. Try analyzing smaller log files or increasing system resources.")
        return None
    except Exception as e:
        print(f"\n🚨 Error analyzing logs: {str(e)}")
        return None


if __name__ == "__main__":
    log_files = ["logs/newlog.log"]
    df = analyze_logs(log_files)
