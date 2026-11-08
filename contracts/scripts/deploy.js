const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const network = hre.network.name;
  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const contract = await ThreatRegistry.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const deployTx = contract.deploymentTransaction();

  const artifact = {
    network,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    contractAddress: address,
    deployTxHash: deployTx.hash,
    blockNumber: deployTx.blockNumber,
    deployedAt: new Date().toISOString(),
  };

  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${network}.json`);
  fs.writeFileSync(outPath, JSON.stringify(artifact, null, 2));
  console.log(JSON.stringify(artifact, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
