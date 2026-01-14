const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying MediVault Smart Contract...");

  const MediVault = await ethers.getContractFactory("MediVaultAccessControl");
  const contract = await MediVault.deploy();

  await contract.waitForDeployment();
  const address = await contract.getAddress();

  console.log("MediVault deployed to:", address);
  console.log("Add this address to your .env file as CONTRACT_ADDRESS");
  
  // Verify on Polygonscan (optional)
  console.log("Waiting for block confirmations...");
  await contract.deploymentTransaction().wait(6);
  
  console.log("Verification command:");
  console.log(`npx hardhat verify --network mumbai ${address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
