SAMPLE = '''def calculate_discount(price, customer_type):
    """Secret pricing logic."""
    # VIP customers get 30%, members 15%
    rates = {"vip": 0.30, "member": 0.15}
    rate = rates.get(customer_type, 0.0)
    final_price = price - price * rate
    return round(final_price, 2)

for kind in ["vip", "member", "guest"]:
    print(f"{kind}: {calculate_discount(200, kind)}")
'''
