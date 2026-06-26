def format_dns_payload(domain):
    """Converts a domain string into DNS wire format."""
    labels = domain.split('.')
    verilog_bytes = []
    
    for label in labels:
        verilog_bytes.append(f"8'h{len(label):02x}")
        for char in label:
            verilog_bytes.append(f"\"{char}\"")
            
    verilog_bytes.append("8'h00")
    total_len = sum(len(l) + 1 for l in labels) + 1
    
    formatted_str = ", ".join(verilog_bytes)
    return formatted_str, total_len

# --- Interactive Mode ---
if __name__ == "__main__":
    try:
        user_input = input("Enter the domain to format (e.g., badge-printer.com): ")
        if user_input:
            verilog_array, length = format_dns_payload(user_input)
            print("\n--- Copy and paste this into tb_hass_top.v ---")
            print(f"send_dns_query_frame({{{verilog_array}}}, {length});")
        else:
            print("No domain entered.")
    except EOFError:
        pass