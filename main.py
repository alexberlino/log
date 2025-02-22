import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import ipaddress
from urllib.parse import urlparse
from collections import Counter
from tabulate import tabulate


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
        'Bing': ['bingbot'],
        'Yandex': ['Yandex', 'YandexBot'],
        'DuckDuckGo': ['DuckDuckBot'],
        'Baidu': ['Baiduspider'],
        'Yahoo': ['Slurp'],
        'Sogou': ['Sogou'],
        'Exabot': ['Exabot'],
        'Facebook': ['facebookexternalhit'],
        'Alexa': ['ia_archiver']
    }
    for engine, patterns in search_engines.items():
        if any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in patterns):
            return engine
    return 'Other' if not re.search(r'(Mozilla|Chrome|Safari|Firefox|Edge|MSIE|Opera)/', user_agent, re.IGNORECASE) else 'Browser'


def analyze_logs(log_files):
    try:
        print("\n🔍 Analyzing search engine crawl patterns...")
        records = []
        other_search_engines = Counter()
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
                        search_engine = identify_search_engine(user_agent)
                        if search_engine not in ['Browser', 'Other']:
                            records.append({
                                'ip': ip, 'datetime': datetime, 'method': method,
                                'url': url, 'status': int(status), 'referer': referer,
                                'user_agent': user_agent, 'search_engine': search_engine
                            })
                            if search_engine not in ['Google', 'Bing']:
                                other_search_engines[search_engine] += 1

        df = pd.DataFrame(records)
        if df.empty:
            print("\n⚠️ No valid log entries found!")
            return None

        df['datetime'] = pd.to_datetime(
            df['datetime'], format="%d/%b/%Y:%H:%M:%S", errors='coerce')
        df = df.sort_values(by="datetime", ascending=False)

        # Create table of other search engines
        top_other_engines = other_search_engines.most_common()
        table_data = [["Search Engine", "Number of Requests"]] + \
            top_other_engines
        table = tabulate(table_data, headers="firstrow", tablefmt="grid")

        # Save table as image
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.axis('off')
        ax.table(cellText=table_data, cellLoc='center', loc='center')
        plt.title("Other Search Engines (Excluding Google and Bing)")
        plt.tight_layout()
        plt.savefig("other_search_engines.png", dpi=300, bbox_inches='tight')
        plt.close()

        print("\n📊 Overview of Search Engine Requests:")
        request_counts = df['search_engine'].value_counts()
        print(request_counts)

        plt.figure(figsize=(8, 5))
        sns.barplot(x=request_counts.index,
                    y=request_counts.values, palette='muted')
        plt.title("Search Engine Request Distribution")
        plt.xlabel("Search Engine")
        plt.ylabel("Number of Requests")
        plt.savefig("search_engine_requests.png")
        plt.close()

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

        # Apply filtering to Googlebot URLs *before* calculating top pages
        googlebot_df = df[df['search_engine'] == 'Google']
        googlebot_df = googlebot_df[~googlebot_df['url'].str.contains(
            r'\.(css|js|png|jpg|jpeg|gif|ico|svg)')]

        top_pages = googlebot_df['url'].value_counts().head(10)

        plt.figure(figsize=(10, 6))
        sns.barplot(y=top_pages.index, x=top_pages.values, palette='coolwarm')
        plt.xlabel("Googlebot Visits")
        plt.ylabel("URL")
        plt.title("Top 10 Pages Crawled by Googlebot")
        plt.savefig("top_googlebot_pages.png")
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
