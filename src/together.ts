import {
  SmartContract,
  Poseidon,
  Field,
  State,
  state,
  PublicKey,
  method,
  UInt32,
  PrivateKey,
  MerkleWitness,
  Permissions,
  Struct,
  Bool,
} from 'snarkyjs';
import { ProposalWithSigns, Proposal } from './utils/proposal';
import { Permit } from './utils/permit';
import { ApproverHashes } from './utils/contract_state';

class ApprovalMerkleWitness extends MerkleWitness(8) {}

class ThresholdUpdate extends Struct({
  contractAddress: PublicKey,
  contractNonce: UInt32,
  newThreshold: UInt32,
}) {}

class Account extends Struct({
  publicKey: PublicKey,
  approvePoints: UInt32,
}) {
  hash(): Field {
    return Poseidon.hash(Account.toFields(this));
  }

  setVotePoints(points: number) {
    return new Account({
      publicKey: this.publicKey,
      approvePoints: UInt32.from(points),
    });
  }
}
// we need the initiate tree root in order to tell the contract about our off-chain storage
let initialCommitment: Field = Field(0);

export class together extends SmartContract {
  // Merkle tree of users
  @state(Field) approversRoot = State<Field>();
  @state(UInt32) approverThreshold = State<UInt32>();
  @state(Field) latestProposalHash = State<Field>();
  @state(ApproverHashes as any) approverHashes = State<ApproverHashes>();

  deploy(args: {
    // approvers: PublicKey[];
    approverPoints: UInt32[];
    approverThreshold: UInt32;
    zkappKey?: PrivateKey | undefined;
    verificationKey?:
      | {
          data: string;
          hash: string | Field;
        }
      | undefined;
    index: bigint;
  }) {
    super.deploy(args);
    this.approverThreshold.set(args.approverThreshold);
    this.latestProposalHash.set(Field(0));
  }

  getWeightOfSigner(
    approver: PublicKey,
    approverPoints: UInt32,
    path: ApprovalMerkleWitness
  ): UInt32 {
    const newApprover = new Account({
      publicKey: approver as PublicKey,
      approvePoints: approverPoints as UInt32,
    });

    const root = this.approversRoot.get();
    root.assertEquals(root);
    const equal = Bool(path.calculateRoot(newApprover.hash()) === root);
    if (equal) {
      return approverPoints;
    } else {
      return new UInt32(0);
    }
  }

  @method init() {
    super.init();
    this.approversRoot.set(initialCommitment);
    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proof(),
      send: Permissions.proof(),
      incrementNonce: Permissions.proof(),
      setVerificationKey: Permissions.proof(),
      setPermissions: Permissions.proof(),
      setDelegate: Permissions.proof(),
      setVotingFor: Permissions.proof(),
      setZkappUri: Permissions.proof(),
      setTokenSymbol: Permissions.proof(),
    });
  }

  @method
  sendAssets(proposalWithSigns: ProposalWithSigns) {
    let approverHashes = this.approverHashes.get();
    this.approverHashes.assertEquals(approverHashes);

    let approverThreshold = this.approverThreshold.get();
    this.approverThreshold.assertEquals(approverThreshold);

    // In order to prevent replay attacks, it is necessary to check the contractAddress and
    // contractNonce in the signature, and the nonce of the contract also needs to be incremented
    // in each transaction.
    let proposal = proposalWithSigns.proposal;
    this.account.nonce.assertEquals(proposal.contractNonce);
    this.self.publicKey.assertEquals(proposal.contractAddress);
    this.self.body.incrementNonce = Bool(true);

    proposalWithSigns
      .verify(approverHashes, approverThreshold)
      .assertTrue(
        'Proposal has wrong signature or does not meet apporverThreshold'
      );

    this.send({
      to: proposalWithSigns.proposal.receiver,
      amount: proposalWithSigns.proposal.amount,
    });

    this.latestProposalHash.set(Poseidon.hash(Proposal.toFields(proposal)));

    this.emitEvent('proposal', proposal);
  }

  @method
  approvePermit(permit: Permit): Bool {
    return this.approvePermitInternal(permit);
  }

  approvePermitInternal(permit: Permit): Bool {
    let approverHashes = this.approverHashes.get();
    this.approverHashes.assertEquals(approverHashes);

    let approverThreshold = this.approverThreshold.get();
    this.approverThreshold.assertEquals(approverThreshold);

    return permit.verify(approverHashes, approverThreshold);
  }

  @method
  updateApproverThreshold(permit: Permit, update: ThresholdUpdate) {
    let authDataHash = Poseidon.hash(ThresholdUpdate.toFields(update));
    permit.authDataHash.assertEquals(
      authDataHash,
      'Permit and ThresholdUpdate must be consistent'
    );

    this.account.nonce.assertEquals(update.contractNonce);
    this.self.publicKey.assertEquals(update.contractAddress);
    this.self.body.incrementNonce = Bool(true);

    this.approvePermitInternal(permit).assertTrue('Permit verification failed');
    this.approverThreshold.set(update.newThreshold);

    this.emitEvent('thresholdUpdate', update);
  }
}

let approversRoot: any;
// This way merkle tree recursively generate
const recursiveMerkleTreeGenerate = (
  approvers: PublicKey[],
  approverPoints: UInt32[],
  hash: Field,
  path: ApprovalMerkleWitness
): Field => {
  if (approvers.length == 0) return hash;
  else {
    let approver = approvers.pop();
    let approverPoint = approverPoints.pop();
    // make sure there is the approver at the index
    approver?.isEmpty().assertEquals(false);
    // create a new approver
    const newApprover = new Account({
      publicKey: approver as PublicKey,
      approvePoints: approverPoint as UInt32,
    });
    const newApproversRoot = path.calculateRoot(newApprover.hash());

    approversRoot.set(newApproversRoot);
    return recursiveMerkleTreeGenerate(approvers, approverPoints, hash, path);
  }
};
