import hre from "hardhat";

async function main() {
  const CTIAnchor = await hre.ethers.getContractFactory("CTIAnchor");
  const contract = await CTIAnchor.deploy();
  await contract.waitForDeployment();
  
  console.log("CTIAnchor deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});