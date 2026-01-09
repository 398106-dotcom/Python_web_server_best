import webview
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

def fetch_and_display(url):
    try:
        # Trim any extra whitespace from the URL
        url = url.strip()

        # Define the headers to include ngrok-skip-browser-warning
        headers = {
            "ngrok-skip-browser-warning": "true"
        }

        # Check if the URL is accessible
        response = requests.get(url, headers=headers, verify=False)  # Disable SSL verification for localhost
        response.raise_for_status()  # Raise an error for bad status codes

        # Create a webview window and load the URL directly
        webview.create_window("Web App", url=url)
        webview.start()
    except requests.ConnectionError:
        print("The server is not running or the URL is incorrect.")
        webview.create_window("Error", html="<h1>Connection Error</h1><p>The server is not running or the URL is incorrect.</p>")
        webview.start()
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        webview.create_window("Error", html=f"<h1>Request Error</h1><p>Error fetching the URL: {e}</p>")
        webview.start()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        webview.create_window("Error", html=f"<h1>Unexpected Error</h1><p>An unexpected error occurred: {e}</p>")
        webview.start()

if __name__ == "__main__":
    url = "https://benignant-unenigmatically-kingsley.ngrok-free.dev"
    fetch_and_display(url)