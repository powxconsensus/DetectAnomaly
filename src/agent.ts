import {
  BlockEvent,
  Finding,
  HandleBlock,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  getJsonRpcUrl
} from "forta-agent";

export const ERC20_TRANSFER_EVENT =
  "event Transfer(address indexed from, address indexed to, uint256 value)";
export const TETHER_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
export const TETHER_DECIMALS = 6;
let findingsCount = 0;

const mapTransFerAmount:any = {};
// detect reentrancy attack 

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];
    // filter the transaction logs for Tether transfer events
    const tetherTransferEvents = txEvent.filterLog(ERC20_TRANSFER_EVENT, TETHER_ADDRESS);
    // for each Tether transfer event
    tetherTransferEvents.forEach((transferEvent) => {
      // extract transfer event arguments
      const { to, from, value } = transferEvent.args;
      const key:string = to+from+value;
      if(key in mapTransFerAmount){
        mapTransFerAmount[key]++;
      }else{
        mapTransFerAmount[key]=1;
      }
      console.log(key);
      
      // shift decimals of transfer value
      const normalizedValue = value.div(10 ** TETHER_DECIMALS);
      // if more than 10,000 Tether were transferred, report it
      if (normalizedValue.gt(1)) {
        findings.push(
          Finding.fromObject({
            name: "High Tether Transfer",
            description: `High amount of USDT transferred: ${normalizedValue}`,
            alertId: "FORTA-1",
            severity: FindingSeverity.Low,
            type: FindingType.Info,
            metadata: {
              to,
              from,
            },
          })
        );
      }else{
        if(mapTransFerAmount[key] > 10){ // Recursive tranfer of same amount
          Finding.fromObject({
            name: "Recursive tranfer",
            description: `Recursive tranfer amount of USDT transferred: ${normalizedValue}`,
            alertId: "FORTA-1",
            severity: FindingSeverity.High,
            type: FindingType.Info,
            metadata: {
              to,
              from,
            },
          })
        }
      }
    });
    // after every hour set mapTransFerAmount this as empty object
    return findings;
};

// const handleBlock: HandleBlock = async (blockEvent: BlockEvent) => {
//   const findings: Finding[] = [];
//   // detect some block condition
//   return findings;
// }

export default {
  handleTransaction,
  // handleBlock
};

