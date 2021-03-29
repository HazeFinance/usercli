require('dotenv').config()
const fs = require('fs')
const Web3 = require('web3')
const { toWei, fromWei, toBN, BN } = require('web3-utils')
const assert = require('assert')
const snarkjs = require('snarkjs')
const crypto = require('crypto')
const circomlib = require('circomlib')
const merkleTree = require('./lib/MerkleTree')
const websnarkUtils = require('websnark/src/utils')
const {HAZE_ADDRESSES, HAZE_PROPERTIES, HAZE_COMMON_ABIS} = require('haze-config');
const Utils = require('./utils')

// TODO
const GAS_LIMIT = 2e6;
const CONTRACT_CREATION_BLOCK_ESTIMATE = 5000000;

class Haze {
  constructor(web3, circuit, proving_key, groth16, depositEvents) {
    this.web3 = web3;
    this.circuit = circuit;
    this.proving_key = proving_key;
    this.groth16 = groth16;
    this.depositEvents = depositEvents;
  }

  rbigint = (nbytes) => {
    return snarkjs.bigInt.leBuff2int(crypto.randomBytes(nbytes));
  }

  pedersenHash = (data) => {
    return circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0];
  }

  getHazeContract = async (depositToken, depositAmount) => {
    const netId =  await this.web3.eth.net.getId();
    const hazeContract = new this.web3.eth.Contract(HAZE_COMMON_ABIS['Hazer'], HAZE_ADDRESSES[`${netId}`]['Hazer'][depositToken][depositAmount]);

    return hazeContract;
  }

  getTokenContract = async (token) => {
    const netId =  await this.web3.eth.net.getId();
    const tokenContract = new this.web3.eth.Contract(HAZE_COMMON_ABIS['ERC20'], HAZE_ADDRESSES[`${netId}`][token]);

    return tokenContract;
  }

  getDepositRewardContract = async () => {
    const netId = await this.web3.eth.net.getId();
    const depositRewardContract = new this.web3.eth.Contract(HAZE_COMMON_ABIS['DepositReward'], HAZE_ADDRESSES[`${netId}`]['DepositReward']);

    return depositRewardContract;
  }

  deposit = async (depositToken, depositAmount) => {
    console.log("preparing for deposit");
    const hazeContract = await this.getHazeContract(depositToken, depositAmount);

    await this.checkAllowanceAndApprove(depositToken, hazeContract.options.address);

    const netId =  await this.web3.eth.net.getId();
    const deposit = this.createDeposit(this.rbigint(31), this.rbigint(31));
    const secret = this.toHex(deposit.preimage, 62);
    const privateNote = `haze-${depositToken}-${depositAmount}-${netId}-${secret}`;
    console.log(`your private note is=${privateNote}`);
    await hazeContract.methods.deposit(this.toHex(deposit.commitment)).send({from: this.web3.eth.defaultAccount, gas: 2e6 });

    console.log("done deposit");
    return privateNote;
  }

  withdraw = async (privateNote, recipient) => {
    console.log("preparing for withdraw");
    const { token, amount, netIdInTheNote, deposit } = this.parseNote(privateNote);

    const hazeContract = await this.getHazeContract(token, amount);
    const { proof, args } = await this.generateProof(hazeContract, token, amount, deposit, recipient);

    await hazeContract.methods.withdraw(proof, ...args).send({from: this.web3.eth.defaultAccount, gas: 2e6 })
      .on('transactionHash', function (txHash) {
        //console.log(`The transaction hash is ${txHash}`);
      }).on('error', function (e) {
        console.error('on transactionHash error', e.message);
        throw new Error('withdraw transaction failed: ' + e.message);
      })

    console.log('done withdraw');
  }

  getCurrentHazeRewardPerDepositInWei = async (depositToken, depositAmount) => {
    const hazeContract = await this.getHazeContract(depositToken, depositAmount);
    const rewardEnabled = await hazeContract.methods.enableReward().call();
    if (!rewardEnabled) {
      return 0;
    }

    const depositRewardContract = await this.getDepositRewardContract();
    const rewardPerDollar = new BN(await depositRewardContract.methods.rewardPerDollar().call());
    const hazerDollarValue = new BN(await depositRewardContract.methods.hazerDollarValue(hazeContract.options.address).call());
    const rewardPerDeposit = rewardPerDollar.mul(hazerDollarValue);

    return rewardPerDeposit;
  }

  parseNote = (privateNote) => {
    const noteRegex = /haze-(?<token>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/g;
    const match = noteRegex.exec(privateNote);

    if (!match) {
      console.log(`The note has invalid format=${privateNote}`);
      throw new Error('The note has invalid format');
    }

    const buf = Buffer.from(match.groups.note, 'hex');
    const nullifier = snarkjs.bigInt.leBuff2int(buf.slice(0, 31));
    const secret = snarkjs.bigInt.leBuff2int(buf.slice(31, 62));
    const deposit = this.createDeposit(nullifier, secret);
    const netId = Number(match.groups.netId)

    return { token: match.groups.token, amount: match.groups.amount, netId, deposit }
  }

  /**
   * Generate SNARK proof for withdrawal
   * @param hazeContract haze contract instance
   * @param deposit Deposit object
   * @param recipient Funds recipient
   * @param relayer Relayer address
   * @param fee Relayer fee
   * @param refund Receive ether for exchanged tokens
   */
  generateProof = async (hazeContract, token, amount, deposit, recipient, relayerAddress = 0, fee = 0, refund = 0) => {
    // Compute merkle proof of our commitment
    const { root, path_elements, path_index } = await this.generateMerkleProof(hazeContract, token, amount, deposit);

    // Prepare circuit input
    const input = {
      // Public snark inputs
      root: root,
      nullifierHash: deposit.nullifierHash,
      recipient: (snarkjs.bigInt)(recipient),
      relayer: (snarkjs.bigInt)(relayerAddress),
      fee: (snarkjs.bigInt)(fee),
      refund: (snarkjs.bigInt)(refund),

      // Private snark inputs
      nullifier: deposit.nullifier,
      secret: deposit.secret,
      pathElements: path_elements,
      pathIndices: path_index,
    }

    const proofData = await websnarkUtils.genWitnessAndProve(this.groth16, input, this.circuit, this.proving_key);
    const { proof } = websnarkUtils.toSolidityInput(proofData);

    const args = [
      this.toHex(input.root),
      this.toHex(input.nullifierHash),
      this.toHex(input.recipient, 20),
      this.toHex(input.relayer, 20),
      this.toHex(input.fee),
      this.toHex(input.refund)
    ]

    return { proof, args }
  }

  /**
   * Generate merkle tree for a deposit.
   * Download deposit events from the haze, reconstructs merkle tree, finds our deposit leaf
   * in it and generates merkle proof
   * @param hazeContract haze contract instance
   * @param deposit Deposit object
   */
  generateMerkleProof = async (hazeContract, token, amount, deposit) => {
    // Get all deposit events from smart contract and assemble merkle tree from them
    const netId = await this.web3.eth.net.getId();
    const events = await this.getAllDepositEvents(hazeContract, token, amount);

    const leaves = events
      .sort((a, b) => a.leafIndex - b.leafIndex)
      .map(e => e.commitment);

    const tree = new merkleTree(HAZE_PROPERTIES[`${netId}`][token][amount]['merkleTreeHeight'], leaves)

    // Find current commitment in the tree
    const depositEvent = events.find(e => e.commitment === this.toHex(deposit.commitment))
    const leafIndex = depositEvent ? depositEvent.leafIndex : -1

    // Validate that our data is correct
    const root = await tree.root()
    const isValidRoot = await hazeContract.methods.isKnownRoot(this.toHex(root)).call()
    const isSpent = await hazeContract.methods.isSpent(this.toHex(deposit.nullifierHash)).call()
    assert(isValidRoot === true, 'Merkle tree is corrupted')
    assert(isSpent === false, 'The note is already spent')
    assert(leafIndex >= 0, 'The deposit is not found in the tree')

    // Compute merkle proof of our commitment
    return tree.path(leafIndex)
  }

  getAllDepositEvents = async (hazeContract, token, amount) => {
    let newEvents = await utils.getPastEventsLimitedBlockRange(hazeContract, 'Deposit', {}, this.depositEvents[token][amount]['toBlock'] + 1, await this.web3.eth.getBlockNumber());
    newEvents = newEvents.map(e => {
      return {'commitment': e.returnValues.commitment, 'leafIndex': e.returnValues.leafIndex, 'timestamp': e.returnValues.timestamp};
    });
    const allEvents = this.depositEvents[token][amount]['events'].concat(newEvents);

    return allEvents;
  }

  checkAllowanceAndApprove = async (token, spenderAddress) => {
    const tokenContract = await this.getTokenContract(token);
    const allowance = await tokenContract.methods.allowance(this.web3.eth.defaultAccount, spenderAddress).call();
    const hasAllowance = toBN(allowance).gt(toBN(0));

    if (!hasAllowance) {
      console.log(`token=${token}, account=${this.web3.eth.defaultAccount}, currentAllowance=${allowance}, approving more tokens`);
      const maxAllowance = new BN(2).pow(new BN(256)).sub(new BN(1));
      await tokenContract.methods.approve(spenderAddress, maxAllowance).send({from: this.web3.eth.defaultAccount, gas: 2e6});
    }
  }

  createDeposit = (nullifier, secret) => {
    const deposit = { nullifier, secret };
    deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)]);
    deposit.commitment = this.pedersenHash(deposit.preimage);
    deposit.commitmentHex = this.toHex(deposit.commitment);
    deposit.nullifierHash = this.pedersenHash(deposit.nullifier.leInt2Buff(31));
    deposit.nullifierHex = this.toHex(deposit.nullifierHash);

    return deposit;
  }

  /** BigNumber to hex string of specified length */
  toHex = (number, length = 32) => {
    const str = number instanceof Buffer ? number.toString('hex') : (snarkjs.bigInt)(number).toString(16);
    return '0x' + str.padStart(length * 2, '0');
  }
}


module.exports = Haze
