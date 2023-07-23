import {
  Bool,
  Circuit,
  Encoding,
  Field,
  PublicKey,
  Signature,
  Struct,
  UInt32,
  UInt64,
} from 'snarkyjs';
import {
  DUMMY_PRIVATEKEY,
  DUMMY_PUBLICKEY,
  MAX_APPROVER_NUM,
} from '../constants';
import { verifySignByApprovers } from '../provable';
import { ApproverHashes } from './contract_state';

export { Proposal, ProposalWithSigns };

class Proposal extends Struct({
  contractAddress: PublicKey,
  contractNonce: UInt32,
  amount: UInt64,
  receiver: PublicKey,
  signThreshold: UInt32,
}) {
  static create(value: {
    contractAddress: PublicKey;
    contractNonce: UInt32;
    desc: string;
    amount: UInt64;
    receiver: PublicKey;
    signThreshold: UInt32;
  }): Proposal {
    value.signThreshold.assertLessThanOrEqual(new UInt32(MAX_APPROVER_NUM));
    let proposal = new Proposal({
      contractAddress: value.contractAddress,
      contractNonce: value.contractNonce,
      amount: value.amount,
      receiver: value.receiver,
      signThreshold: value.signThreshold,
    });

    return proposal;
  }
}

class ProposalWithSigns extends Struct({
  proposal: Proposal,
  approvers: Circuit.array(PublicKey, MAX_APPROVER_NUM),
  signs: Circuit.array(Signature, MAX_APPROVER_NUM),
}) {
  static create(
    proposal: Proposal,
    approvers?: PublicKey[],
    signs?: Signature[]
  ): ProposalWithSigns {
    return new ProposalWithSigns({
      proposal,
      approvers: approvers ? approvers : [],
      signs: signs ? signs : [],
    });
  }

  padding() {
    let approversLen = this.approvers.length;
    if (approversLen < MAX_APPROVER_NUM) {
      this.approvers = this.approvers.concat(
        Array(MAX_APPROVER_NUM - approversLen).fill(DUMMY_PUBLICKEY)
      );
    }

    let signsLen = this.signs.length;
    if (signsLen < MAX_APPROVER_NUM) {
      this.signs = this.signs.concat(
        Array(MAX_APPROVER_NUM - signsLen).fill(
          Signature.create(DUMMY_PRIVATEKEY, [Field(0)])
        )
      );
    }
  }

  addSignWithPublicKey(sign: Signature, publicKey: PublicKey) {
    if (!this.proposal) {
      throw new Error(`Proposal has not been initialized`);
    }
    if (!this.signs) {
      this.signs = [];
    }

    if (
      this.signs.length > MAX_APPROVER_NUM ||
      this.approvers.length > MAX_APPROVER_NUM
    ) {
      throw new Error(
        `The number of Approver or Signature is greater than the limit: ${MAX_APPROVER_NUM}`
      );
    }

    this.signs.push(sign);
    this.approvers.push(publicKey);
  }

  // verify proposal
  verify(approverHashes: ApproverHashes, approverThreshold: UInt32): Bool {
    let signFields = Proposal.toFields(this.proposal);

    return verifySignByApprovers(
      signFields,
      this.signs,
      this.approvers,
      approverHashes,
      approverThreshold
    );
  }
}
