import os
import json
import hashlib
from pinatapy import PinataPy

# Replace with your actual Pinata JWT token
PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiIxN2Y2ZDliZi1jYTA0LTQxMzMtOTFhMy02NTI1M2VkMWM5MzAiLCJlbWFpbCI6InN1cnlhdGVqdm9qamFsYUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGluX3BvbGljeSI6eyJyZWdpb25zIjpbeyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJGUkExIn0seyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJOWUMxIn1dLCJ2ZXJzaW9uIjoxfSwibWZhX2VuYWJsZWQiOmZhbHNlLCJzdGF0dXMiOiJBQ1RJVkUifSwiYXV0aGVudGljYXRpb25UeXBlIjoic2NvcGVkS2V5Iiwic2NvcGVkS2V5S2V5IjoiMmZiOWI5MDQ5OGRiZWRhMmMzMGIiLCJzY29wZWRLZXlTZWNyZXQiOiI3NzlmMWY0N2I0ODZkMWZmMTI5NzIxMzkzMzBjNjg1MjA3NGFiZmE4ZGEwNWQxZTcxZDY3NTA2MmVmMDg4MWUwIiwiZXhwIjoxODE1MDE4NzUzfQ.Ybq409MD2rc6tUpG_T1VM7uYf6cHFLyyQNHQrNoYhCg"

def upload_to_ipfs(file_path: str) -> dict:
    """
    Upload a CTI report to IPFS via Pinata.
    Returns the IPFS CID and file metadata.
    """
    pinata = PinataPy(pinata_jwt=PINATA_JWT)
    
    file_name = os.path.basename(file_path)
    
    print(f"Uploading {file_name} to IPFS...")
    
    response = pinata.pin_file_to_ipfs(
        file_path,
        ipfs_destination_path=file_name
    )
    
    cid = response["IpfsHash"]
    
    print(f"Successfully uploaded to IPFS!")
    print(f"CID: {cid}")
    print(f"View at: https://gateway.pinata.cloud/ipfs/{cid}")
    
    return {
        "cid": cid,
        "file_name": file_name,
        "ipfs_url": f"https://gateway.pinata.cloud/ipfs/{cid}"
    }

if __name__ == "__main__":
    # Test with your sample report
    result = upload_to_ipfs("test_report.txt")
    print(json.dumps(result, indent=2))