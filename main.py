import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import ipaddress
import dns.resolver
from urllib.parse import urlparse, parse_qs

def is_google_ip(ip):
    """Verify if IP belongs to Google's crawler network"""
    try:
        google_ranges = [
            "66.249.64.0/19", "66.249.80.0/20", "64.233.160.0/19", "216.239.32.0/19"
        ]
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(net) for net in google_ranges)
    except:
        return False

def is_googlebot_ua(user_agent):
    """Improved Googlebot user agent detection"""
    googlebot_patterns = [
        r'compatible;\s+Googlebot/', r'Googlebot-\w+/', r'AdsBot-Google',
        r'APIs-Google', r'Google-Read-Aloud', r'FeedFetcher-Google', r'Google-Site-Verification'
    ]
    return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in googlebot_patterns)

def analyze_logs(log_files):
    try:
        print("\n🔍 Analyzing Googlebot crawl patterns...")
        records = []
        total_lines = 0
        googlebot_lines = 0
        
        # Read and combine multiple log files
        for log_file in log_files:
            print(f"\n📂 Processing {log_file}...")
            with open(log_file, 'r') as f:
                for line in f:
                    total_lines += 1
                    if 'Googlebot' in line:
                        googlebot_lines += 1
                        if googlebot_lines <= 5:
                            print(f"Found: {line.strip()}")
                    
                    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(\w+) (.*?) HTTP.*?" (\d+) .*?"(.*?)" "(.*?)"'
                    match = re.search(pattern, line)
                    if match:
                        ip, datetime, method, url, status, referer, user_agent = match.groups()
                        records.append({
                            'ip': ip, 'datetime': datetime, 'method': method,
                            'url': url, 'status': int(status), 'referer': referer, 'user_agent': user_agent
                        })
        
        # Convert records into a DataFrame
        df = pd.DataFrame(records)
        if df.empty:
            print("\n⚠️ No valid log entries found!")
            return None, None
        
        googlebot_mask = df['user_agent'].apply(is_googlebot_ua)
        ip_mask = df['ip'].apply(is_google_ip)
        verified_googlebot = df[googlebot_mask & ip_mask].copy()
        
        print("\n✅ Verified Googlebot requests:", len(verified_googlebot))
        if not verified_googlebot.empty:
            verified_googlebot["datetime"] = pd.to_datetime(
                verified_googlebot["datetime"].str.strip("[]"), 
                format="%d/%b/%Y:%H:%M:%S", errors='coerce'
            )
            
            # Print summary data
            print("\n🔗 URLs crawled by Googlebot:")
            print(verified_googlebot[['url', 'status', 'datetime']].sort_values('datetime'))
            print("\n📊 Status Code Distribution:")
            print(verified_googlebot['status'].value_counts())
            
            extensions = verified_googlebot['url'].apply(lambda x: x.split('.')[-1] if '.' in x else 'no_extension')
            print("\n📁 Resource Types Crawled:")
            print(extensions.value_counts())
            
            static_files = verified_googlebot[verified_googlebot['url'].str.contains(r'\.(css|js|svg|png|jpg|jpeg|gif)$', case=False)]
            if not static_files.empty:
                print("\n💡 Recommendations:")
                print("1. Consider blocking static resources in robots.txt")
            
            # Visualization
            plt.figure(figsize=(10, 5))
            sns.histplot(verified_googlebot['datetime'], bins=30, kde=True)
            plt.title("Googlebot Crawl Activity Over Time")
            plt.xlabel("Date")
            plt.ylabel("Request Count")
            plt.xticks(rotation=45)
            plt.savefig("googlebot_crawl_activity.png")
            plt.show()
            
            status_counts = verified_googlebot['status'].value_counts()
            plt.figure(figsize=(8, 5))
            sns.barplot(x=status_counts.index, y=status_counts.values, palette='viridis')
            plt.title("Status Code Distribution")
            plt.xlabel("Status Code")
            plt.ylabel("Count")
            plt.savefig("status_code_distribution.png")
            plt.show()
            
            top_crawled_pages = verified_googlebot['url'].value_counts().head(10)
            print("\n🏆 Top 10 Most Crawled Pages:")
            print(top_crawled_pages)
        
        return df, verified_googlebot
        
    except MemoryError:
        print("\n🚨 Error: Memory usage exceeded. Try analyzing smaller log files or increasing system resources.")
        return None, None
    except Exception as e:
        print(f"\n🚨 Error analyzing logs: {str(e)}")
        return None, None

if __name__ == "__main__":
    log_files = ["1.log", "2.log", "3.log", "4.log"]
    df, googlebot_df = analyze_logs(log_files)
