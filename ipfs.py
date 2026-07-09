import os
import requests

PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiIxN2Y2ZDliZi1jYTA0LTQxMzMtOTFhMy02NTI1M2VkMWM5MzAiLCJlbWFpbCI6InN1cnlhdGVqdm9qamFsYUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGluX3BvbGljeSI6eyJyZWdpb25zIjpbeyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJGUkExIn0seyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJOWUMxIn1dLCJ2ZXJzaW9uIjoxfSwibWZhX2VuYWJsZWQiOmZhbHNlLCJzdGF0dXMiOiJBQ1RJVkUifSwiYXV0aGVudGljYXRpb25UeXBlIjoic2NvcGVkS2V5Iiwic2NvcGVkS2V5S2V5IjoiMmZiOWI5MDQ5OGRiZWRhMmMzMGIiLCJzY29wZWRLZXlTZWNyZXQiOiI3NzlmMWY0N2I0ODZkMWZmMTI5NzIxMzkzMzBjNjg1MjA3NGFiZmE4ZGEwNWQxZTcxZDY3NTA2MmVmMDg4MWUwIiwiZXhwIjoxODE1MDE4NzUzfQ.Ybq409MD2rc6tUpG_T1VM7uYf6cHFLyyQNHQrNoYhCg"

def upload_to_ipfs(file_path: str) -> str:
    """
    Upload a CTI report to IPFS via Pinata.
    Returns the IPFS CID string.
    """
    file_name = os.path.basename(file_path)

    with open(file_path, "rb") as f:
        files = {
            "file": (file_name, f)
        }
        headers = {
            "Authorization": f"Bearer {PINATA_JWT}"
        }
        response = requests.post(
            "https://api.pinata.cloud/pinning/pinFileToIPFS",
            files=files,
            headers=headers
        )

    if response.status_code == 200:
        cid = response.json()["IpfsHash"]
        print(f"Uploaded to IPFS! CID: {cid}")
        return cid
    else:
        raise Exception(f"Pinata upload failed: {response.status_code} - {response.text}")

if __name__ == "__main__":
    result = upload_to_ipfs("test_report.txt")
    print(f"CID: {result}")
    print(f"URL: https://gateway.pinata.cloud/ipfs/{result}")