# Anomaly Detection Logic

def check_dns_anomalies(resolvers, domain_to_monitor):
    anomalies = {"DNS Hijacking": [], "DNS Spoofing": [], "DNS Cache Poisoning": [], "DNS Resolver Spoofing": [], "DNS Resolver Cache Poisoning": [], "DNS Sequence Number Guessing": []}

    for resolver in resolvers:
        if is_dns_hijacking(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Hijacking"].append(resolver.ip)

        if is_dns_spoofing(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Spoofing"].append(resolver.ip)

        if is_dns_cache_poisoning(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Cache Poisoning"].append(resolver.ip)

        if is_dns_resolver_spoofing(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Resolver Spoofing"].append(resolver.ip)

        if is_dns_resolver_cache_poisoning(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Resolver Cache Poisoning"].append(resolver.ip)

        if is_dns_sequence_number_guessing(resolver, domain_to_monitor, resolver.responses):
            anomalies["DNS Sequence Number Guessing"].append(resolver.ip)

    return anomalies
