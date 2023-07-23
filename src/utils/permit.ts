import {
  Bool,
  Circuit,
  Field,
  PublicKey,
  Signature,
  Struct,
  UInt32,
} from 'snarkyjs';
import {
  DUMMY_PRIVATEKEY,
  DUMMY_PUBLICKEY,
  MAX_APPROVER_NUM,
} from '../constants';
import { verifySignByApprovers } from '../provable';
import { ApproverHashes } from './contract_state';

export { Permit };

class Permit extends Struct({
  authDataHash: Field,
  approvers: Circuit.array(PublicKey, MAX_APPROVER_NUM),
  signs: Circuit.array(Signature, MAX_APPROVER_NUM),
}) {
  static create(
    authDataHash: Field,
    approvers?: PublicKey[],
    signs?: Signature[]
  ): Permit {
    return new Permit({
      authDataHash,
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
    if (!this.approvers) {
      this.approvers = [];
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

  verify(approverHashes: ApproverHashes, approverThreshold: UInt32): Bool {
    let signFields = [this.authDataHash];

    return verifySignByApprovers(
      signFields,
      this.signs,
      this.approvers,
      approverHashes,
      approverThreshold
    );
  }
}
