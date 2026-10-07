import asyncio
import requests
import json


async def async_scan(url):
    loop = asyncio.get_running_loop()

    try:
        response = await loop.run_in_executor(
            None,
            lambda: requests.get(url, timeout=10)
        )

        return {
            "url": url,
            "status": "Success",
            "status_code": response.status_code,
            "response_time": round(
                response.elapsed.total_seconds(),
                3
            )
        }

    except requests.RequestException as error:

        return {
            "url": url,
            "status": "Failed",
            "status_code": None,
            "response_time": None,
            "error": str(error)
        }


async def main():

    urls = [
        "https://example.com",
        "https://www.google.com",
        "https://www.wikipedia.org"
    ]

    print("\n--- Async Multi-URL Scan ---")

    tasks = []

    for url in urls:
        tasks.append(async_scan(url))

    results = await asyncio.gather(*tasks)

    for result in results:

        print("\nURL:", result["url"])
        print("Status:", result["status"])

        if result["status"] == "Success":

            print("Status Code:", result["status_code"])
            print(
                "Response Time:",
                result["response_time"],
                "seconds"
            )

        else:

            print("Status Code: Not Available")
            print("Response Time: Not Available")
            print("Error:", result["error"])

    with open("async_results.json", "w") as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print("\nResults saved to async_results.json")


if __name__ == "__main__":
    asyncio.run(main())