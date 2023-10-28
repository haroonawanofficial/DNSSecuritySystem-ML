# data_collection.py

def collect_dns_records(domain, custom_dns_servers=None):
    # Collect DNS records for the main domain (A, MX, CNAME, TXT, NS, PTR)
    main_domain_records = collect_dns_records_main_domain(domain, custom_dns_servers)

    # Collect DNS records for neighboring DNS servers
    neighboring_dns_records = collect_neighboring_dns_records(neighboring_dns_servers)

    return main_domain_records, neighboring_dns_records
