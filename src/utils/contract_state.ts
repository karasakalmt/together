import { Bool, Circuit, Field, Poseidon, PublicKey, Struct } from 'snarkyjs';
import { EMPTY_PUBLICKEY, MAX_APPROVER_NUM } from '../constants';

export { ApproverHashes };

class ApproverHashes extends Struct({
  arr: Circuit.array(Field, MAX_APPROVER_NUM),
}) {
  static createWithPadding(publicKeys: PublicKey[]): ApproverHashes {
    if (publicKeys.length > MAX_APPROVER_NUM) {
      throw new Error(
        `The number of Approvers is greater than the limit: ${MAX_APPROVER_NUM}`
      );
    }

    let hashes = publicKeys.map((v) => Poseidon.hash(v.toFields()));
    if (hashes.length < MAX_APPROVER_NUM) {
      hashes = hashes.concat(
        Array(MAX_APPROVER_NUM - hashes.length).fill(Field(0))
      );
    }

    return new ApproverHashes({ arr: hashes });
  }

  static createInCircuit(publicKeys: PublicKey[]): ApproverHashes {
    let hashes = publicKeys.map((v) => Poseidon.hash(v.toFields()));
    let emptyPublicKeyHash = Poseidon.hash(EMPTY_PUBLICKEY.toFields());
    let newHashes = hashes.map((v) => {
      return v.equals(emptyPublicKeyHash) ? Field(0) : v;
    });

    return new ApproverHashes({ arr: newHashes });
  }

  // check whether the publicKey is approver
  isApproverInCircuit(publicKey: PublicKey): Bool {
    let approverHash = Poseidon.hash(publicKey.toFields());
    let isOneApprover = this.arr
      .map((v) => v.equals(approverHash))
      .reduce(Bool.or);

    return Circuit.if(
      publicKey.equals(PublicKey.empty()),
      Bool(false),
      isOneApprover
    );
  }

  // check outside the circuit
  isApprover(publicKey: PublicKey): boolean {
    if (publicKey.equals(PublicKey.empty()).toBoolean()) {
      return false;
    }

    let approverHash = Poseidon.hash(publicKey.toFields());
    let isOneApprover = this.arr
      .map((v) => v.equals(approverHash).toBoolean())
      .reduce((x: boolean, y: boolean) => {
        return x || y;
      });

    return isOneApprover;
  }
}
