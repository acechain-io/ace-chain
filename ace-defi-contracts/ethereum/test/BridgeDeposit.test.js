const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("BridgeDeposit", function () {
  async function deployFixture() {
    const [owner, user, recipient, other] = await ethers.getSigners();

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const usdt = await MockERC20.deploy("Mock USDT", "USDT", 6);
    const dai = await MockERC20.deploy("Mock DAI", "DAI", 18);

    const BridgeDeposit = await ethers.getContractFactory("BridgeDeposit");
    const bridge = await BridgeDeposit.deploy(await usdt.getAddress());

    await usdt.mint(user.address, 1_000_000n);
    await dai.mint(user.address, 1_000_000n);
    await usdt.connect(user).approve(await bridge.getAddress(), 1_000_000n);
    await dai.connect(user).approve(await bridge.getAddress(), 1_000_000n);

    return { owner, user, recipient, other, bridge, usdt, dai };
  }

  const intentA = ethers.hexlify(ethers.randomBytes(32));
  const intentB = ethers.hexlify(ethers.randomBytes(32));
  const aceRecipient = ethers.hexlify(ethers.randomBytes(32));

  it("emits intent-bound USDT deposit events", async function () {
    const { user, bridge, usdt } = await deployFixture();
    const amount = 123n;
    const expectedDepositId = await bridge
      .connect(user)
      .deposit.staticCall(amount, intentA, aceRecipient);

    await expect(bridge.connect(user).deposit(amount, intentA, aceRecipient))
      .to.emit(bridge, "Deposit")
      .withArgs(
        expectedDepositId,
        intentA,
        user.address,
        await usdt.getAddress(),
        amount,
        aceRecipient,
        anyValue
      );

    expect(await bridge.acceptedDeposits(expectedDepositId)).to.equal(true);
    expect(await bridge.isAcceptedDeposit(expectedDepositId)).to.equal(true);
  });

  it("includes intentId and nonce in unique deposit IDs", async function () {
    const { user, bridge } = await deployFixture();

    const idA = await bridge.connect(user).deposit.staticCall(100n, intentA, aceRecipient);
    await bridge.connect(user).deposit(100n, intentA, aceRecipient);

    const idB = await bridge.connect(user).deposit.staticCall(100n, intentA, aceRecipient);
    await bridge.connect(user).deposit(100n, intentA, aceRecipient);

    const idC = await bridge.connect(user).deposit.staticCall(100n, intentB, aceRecipient);

    expect(idA).to.not.equal(idB);
    expect(idB).to.not.equal(idC);
  });

  it("accepts generic ERC20 deposits with intent IDs", async function () {
    const { user, bridge, dai } = await deployFixture();
    const amount = 456n;
    const expectedDepositId = await bridge
      .connect(user)
      .depositToken.staticCall(await dai.getAddress(), amount, intentA, aceRecipient);

    await expect(
      bridge.connect(user).depositToken(await dai.getAddress(), amount, intentA, aceRecipient)
    )
      .to.emit(bridge, "Deposit")
      .withArgs(
        expectedDepositId,
        intentA,
        user.address,
        await dai.getAddress(),
        amount,
        aceRecipient,
        anyValue
      );
  });

  it("rejects zero intent IDs", async function () {
    const { user, bridge, dai } = await deployFixture();
    const zeroIntent = ethers.ZeroHash;

    await expect(bridge.connect(user).deposit(1n, zeroIntent, aceRecipient)).to.be.revertedWith(
      "Invalid intentId"
    );
    await expect(
      bridge.connect(user).depositToken(await dai.getAddress(), 1n, zeroIntent, aceRecipient)
    ).to.be.revertedWith("Invalid intentId");
  });

  it("requires owner for emergency controls", async function () {
    const { user, recipient, bridge, usdt } = await deployFixture();

    await expect(
      bridge.connect(user).scheduleEmergencyWithdraw(await usdt.getAddress(), recipient.address, 1n)
    ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount");
    await expect(bridge.connect(user).cancelEmergencyWithdraw(ethers.ZeroHash)).to.be
      .revertedWithCustomError(bridge, "OwnableUnauthorizedAccount");
    await expect(
      bridge.connect(user).executeEmergencyWithdraw(ethers.ZeroHash, await usdt.getAddress(), recipient.address, 1n)
    ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount");
  });

  it("schedules, cancels, and executes emergency withdrawals after timelock", async function () {
    const { owner, user, recipient, bridge, usdt } = await deployFixture();
    const bridgeAddress = await bridge.getAddress();

    await bridge.connect(user).deposit(10_000n, intentA, aceRecipient);
    expect(await usdt.balanceOf(bridgeAddress)).to.equal(10_000n);

    const scheduleTx = await bridge
      .connect(owner)
      .scheduleEmergencyWithdraw(await usdt.getAddress(), recipient.address, 1_000n);
    const scheduleReceipt = await scheduleTx.wait();
    const scheduled = scheduleReceipt.logs
      .map((log) => {
        try {
          return bridge.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((event) => event && event.name === "EmergencyWithdrawalScheduled");
    const operationId = scheduled.args.operationId;

    await bridge.connect(owner).cancelEmergencyWithdraw(operationId);
    await expect(
      bridge.connect(owner).executeEmergencyWithdraw(operationId, await usdt.getAddress(), recipient.address, 1_000n)
    ).to.be.revertedWith("Operation not scheduled");

    const secondScheduleTx = await bridge
      .connect(owner)
      .scheduleEmergencyWithdraw(await usdt.getAddress(), recipient.address, 1_000n);
    const secondReceipt = await secondScheduleTx.wait();
    const secondScheduled = secondReceipt.logs
      .map((log) => {
        try {
          return bridge.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((event) => event && event.name === "EmergencyWithdrawalScheduled");
    const secondOperationId = secondScheduled.args.operationId;
    expect(secondOperationId).to.not.equal(operationId);

    await expect(
      bridge.connect(owner).executeEmergencyWithdraw(secondOperationId, await usdt.getAddress(), recipient.address, 1_000n)
    ).to.be.revertedWith("Timelock not expired");

    const delay = await bridge.EMERGENCY_WITHDRAW_DELAY();
    await time.increase(delay);
    await expect(
      bridge.connect(owner).executeEmergencyWithdraw(secondOperationId, await usdt.getAddress(), recipient.address, 999n)
    ).to.be.revertedWith("Operation parameters mismatch");
    await expect(
      bridge.connect(owner).executeEmergencyWithdraw(secondOperationId, await usdt.getAddress(), recipient.address, 1_000n)
    ).to.emit(bridge, "Withdrawal");
    expect(await usdt.balanceOf(recipient.address)).to.equal(1_000n);
  });
});
