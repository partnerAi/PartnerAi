// HST v1.0 — Human-Sovereign-Time Chaincode
// Zero-Default Lending | Mutual NPC Code | A-L-F Veto™
// Architect: Joshua Juice Ba Lacy | JuicyIdeas Co.
// Deployed: 2025-11-13 00:00 HST

'use strict';

const { Contract } = require('fabric-contract-api');

class HSTContract extends Contract {

  // Initialize ledger with genesis pledge
  async initLedger(ctx) {
    const genesis = {
      block: 0,
      timestamp: "2025-11-13T00:00:00-10:00",
      architect: "Joshua Juice Ba Lacy",
      pledge: "I give 1 hour to the weave.",
      hst: 1,
      totalSupply: 1,
      defaultRate: 0.00
    };
    await ctx.stub.putState('GENESIS', Buffer.from(JSON.stringify(genesis)));
    return genesis;
  }

  // Mint HST: 1 verified hour = 1 HST
  async mintHST(ctx, nodeId, participant, effortHours, voiceHash, communityVouch) {
    effortHours = parseInt(effortHours);
    if (isNaN(effortHours) || effortHours <= 0) throw new Error('Invalid effort');

    // A-L-F Veto™: 6-AI consensus (simulated)
    const veto = await this.a_l_f_veto(ctx, effortHours, communityVouch);
    if (!veto.passed) throw new Error(`Veto failed: ${veto.reason}`);

    // Mutual NPC Code: No extraction
    if (communityVouch < 3) throw new Error('Need 3+ vouches');

    const pledgeId = ctx.stub.getTxID();
    const pledge = {
      pledgeId,
      nodeId,
      participant,
      effortHours,
      voiceHash,
      communityVouch,
      timestamp: new Date().toISOString(),
      hstMinted: effortHours,
      status: 'active'
    };

    await ctx.stub.putState(pledgeId, Buffer.from(JSON.stringify(pledge)));

    // Update total supply
    const supplyKey = 'TOTAL_SUPPLY';
    let supply = 0;
    const supplyData = await ctx.stub.getState(supplyKey);
    if (supplyData && supplyData.length > 0) {
      supply = parseInt(supplyData.toString());
    }
    supply += effortHours;
    await ctx.stub.putState(supplyKey, Buffer.from(supply.toString()));

    return { pledgeId, hstMinted: effortHours, totalSupply: supply };
  }

  // A-L-F Veto™ — 6 AI consensus (simulated)
  async a_l_f_veto(ctx, effort, vouch) {
    // In production: call 6 AIs (Gemini, Grok, etc.)
    // Here: 100% pass if vouch >= 3
    if (vouch >= 3 && effort > 0 && effort <= 168) {
      return { passed: true };
    }
    return { passed: false, reason: 'Low vouch or invalid effort' };
  }

  // Bridge Trade: HST → Real Resource
  async bridgeTrade(ctx, fromPledgeId, toResource, amountKg) {
    const pledgeData = await ctx.stub.getState(fromPledgeId);
    if (!pledgeData) throw new Error('Pledge not found');

    const pledge = JSON.parse(pledgeData.toString());
    if (pledge.hstMinted < amountKg) throw new Error('Not enough HST');

    const trade = {
      tradeId: ctx.stub.getTxID(),
      fromPledgeId,
      toResource,
      amountKg,
      status: 'matched',
      timestamp: new Date().toISOString()
    };

    await ctx.stub.putState(trade.tradeId, Buffer.from(JSON.stringify(trade)));
    return trade;
  }

  // Query total HST supply
  async getTotalSupply(ctx) {
    const supplyData = await ctx.stub.getState('TOTAL_SUPPLY');
    return supplyData ? parseInt(supplyData.toString()) : 0;
  }

  // Query pledge by ID
  async getPledge(ctx, pledgeId) {
    const data = await ctx.stub.getState(pledgeId);
    return data ? JSON.parse(data.toString()) : null;
  }
}

module.exports = HSTContract;