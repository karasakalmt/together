import { Bool, Circuit, Field, PublicKey, Signature, UInt32 } from 'snarkyjs';
import {
  DUMMY_PUBLICKEY,
  EMPTY_PUBLICKEY,
  MAX_APPROVER_NUM,
} from './constants';
import { ApproverHashes } from './utils/contract_state';

export { verifySignByApprovers };

function verifySignByApprovers(
  signFields: Field[],
  signs: Signature[],
  signers: PublicKey[],
  approverHashes: ApproverHashes,
  approverThreshold: UInt32
): Bool {
  // check that there are no same signers.
  let isExistSameSigner = Bool(false);
  for (let i = 0; i < signers.length - 1; i++) {
    for (let j = i + 1; j < signers.length; j++) {
      isExistSameSigner = isExistSameSigner.or(
        signers[i]
          .equals(signers[j])
          .and(signers[i].equals(DUMMY_PUBLICKEY).not())
      );
    }
  }

  let tempVerifyResults: Bool[] = [];
  for (let i = 0; i < MAX_APPROVER_NUM; i++) {
    let signature = signs[i];
    let signer = signers[i];
    let isApprover = approverHashes.isApproverInCircuit(signer);
    let signOk = signature.verify(signer, signFields);

    let tempResult = Circuit.if(
      signer.equals(EMPTY_PUBLICKEY),
      Bool(false),
      isApprover.and(signOk)
    );
    tempVerifyResults.push(tempResult);
  }

  let approveCount = UInt32.from(0);
  tempVerifyResults.forEach((v) => {
    approveCount = Circuit.if(v, approveCount.add(1), approveCount);
  });

  return Circuit.if(
    approveCount
      .greaterThanOrEqual(approverThreshold)
      .and(isExistSameSigner.equals(Bool(false))),
    Bool(true),
    Bool(false)
  );
}
