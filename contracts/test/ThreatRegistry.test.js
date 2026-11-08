const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", function () {
  let registry;
  let owner, other;

  const reportId = ethers.encodeBytes32String("report-1");
  const commitment = ethers.encodeBytes32String("commitment-1");
  const revised = ethers.encodeBytes32String("commitment-2");
  const reason = ethers.encodeBytes32String("reason-1");

  beforeEach(async () => {
    [owner, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory("ThreatRegistry");
    registry = await F.deploy();
    await registry.waitForDeployment();
  });

  it("submits a report and emits event", async () => {
    await expect(registry.submitReport(reportId, commitment))
      .to.emit(registry, "ReportSubmitted")
      .withArgs(reportId, commitment, owner.address, (v) => typeof v === "bigint");
    const r = await registry.getReport(reportId);
    expect(r.commitment).to.equal(commitment);
    expect(r.version).to.equal(1);
  });

  it("rejects duplicate report id", async () => {
    await registry.submitReport(reportId, commitment);
    await expect(registry.submitReport(reportId, commitment)).to.be.revertedWithCustomError(
      registry,
      "AlreadyRegistered"
    );
  });

  it("tracks revisions", async () => {
    await registry.submitReport(reportId, commitment);
    await registry.reviseReport(reportId, revised);
    const r = await registry.getReport(reportId);
    expect(r.commitment).to.equal(revised);
    expect(r.version).to.equal(2);
    expect(await registry.revisionCount(reportId)).to.equal(2n);
  });

  it("records disputes and sets status", async () => {
    await registry.submitReport(reportId, commitment);
    await registry.connect(other).disputeReport(reportId, reason);
    const r = await registry.getReport(reportId);
    expect(r.status).to.equal(3); // Disputed
  });

  it("records validation", async () => {
    await registry.submitReport(reportId, commitment);
    await registry.validateReport(reportId, true);
    const r = await registry.getReport(reportId);
    expect(r.status).to.equal(2); // Validated
  });
});
