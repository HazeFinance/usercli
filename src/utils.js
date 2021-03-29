require('dotenv').config()
const Web3 = require('web3')
const { toWei, fromWei, toBN, BN } = require('web3-utils')

Utils = {

  getPastEventsLimitedBlockRange: async function(contract, eventName, filter, fromBlock, toBlock) {
    const MAX_BLOCK_RANGE = 5000;

    let currentBlock = fromBlock;
    let allEvents = [];
    while (currentBlock <= toBlock) {
      const events = await contract.getPastEvents(eventName, {
        filter: filter,
        fromBlock: currentBlock,
        toBlock: Math.min(currentBlock + MAX_BLOCK_RANGE, toBlock)
      });


      allEvents = allEvents.concat(events);
      currentBlock = currentBlock + MAX_BLOCK_RANGE + 1;
    }

    return allEvents;
  },

  // TODO: check if other fields need set
  getWeb3Instance: function (rpc, privateKey) {
    const provider = new Web3.providers.HttpProvider(rpc);
    const web3 = new Web3(provider);
    const account = web3.eth.accounts.privateKeyToAccount('0x' + privateKey);
    web3.eth.accounts.wallet.add('0x' + privateKey);
    web3.eth.defaultAccount = account.address;

    return web3;
  }

}


module.exports = Utils
