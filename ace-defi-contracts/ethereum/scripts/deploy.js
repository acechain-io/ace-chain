const { ethers, network } = require("hardhat");

async function main() {
  const usdtAddress = process.env.USDT_ADDRESS;
  if (!usdtAddress || !ethers.isAddress(usdtAddress)) {
    throw new Error("USDT_ADDRESS must be set to a valid ERC20 token address");
  }

  const BridgeDeposit = await ethers.getContractFactory("BridgeDeposit");
  const bridge = await BridgeDeposit.deploy(usdtAddress);
  await bridge.waitForDeployment();

  console.log(`network=${network.name}`);
  console.log(`usdt=${usdtAddress}`);
  console.log(`bridge=${await bridge.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
