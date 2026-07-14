from ipfs import upload_to_ipfs

cid = upload_to_ipfs("CCNCS_TEST.txt")

print("\n✅ Upload Successful!")
print("CID:", cid)
print(f"\nGateway URL:\nhttps://gateway.pinata.cloud/ipfs/{cid}")