def store_api_key():
    api_key = input("Please enter your VirusTotal API key: ")
    with open("api_key.txt", "w") as file:
        file.write(api_key)
    print("API key saved successfully.")

def get_api_key():
    try:
        with open("api_key.txt", "r") as file:
            api_key = file.read().strip()
            return api_key
    except FileNotFoundError:
        print("API key file not found. Please hit enter and follow the steps to store your API key:")
        return None
