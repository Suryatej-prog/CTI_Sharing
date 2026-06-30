import { network } from "hardhat";

async function main() {
  const { ethers } = await network.connect({ network: "localhost" });

  const CTIAnchor = await ethers.getContractFactory("CTIAnchor");
  const contract = await CTIAnchor.deploy();
  await contract.waitForDeployment();

  console.log("CTIAnchor deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});