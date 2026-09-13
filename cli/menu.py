def run_menu():
    while True:
        print("\n--- Network Sentinel Menu ---")
        print("1. Monitor Network")
        print("2. View Devices")
        print("3. View Alerts")
        print("4. Build Baseline")
        print("5. Generate Report")
        print("6. Exit")
        choice = input("Select an option: ")
        
        if choice == '1':
            print("Monitoring started... (Ctrl+C to stop)")
            # Add call to monitoring logic
        elif choice == '6':
            print("Exiting Network Sentinel. Stay safe!")
            break
        else:
            print("Option not implemented yet.")
