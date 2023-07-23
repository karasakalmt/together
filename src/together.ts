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
  Circuit,
} from 'snarkyjs';
import { ProposalWithSigns, Proposal } from './utils/proposal';
import { ApproverHashes } from './utils/contract_state';
import { MAX_APPROVER_NUM } from './constants';

class ApprovalMerkleWitness extends MerkleWitness(8) {}

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

  getWeightOfBatchSigner(
    approvers: PublicKey[],
    approverPoints: UInt32[],
    paths: ApprovalMerkleWitness[]
  ): UInt32 {
    let total: UInt32 = new UInt32(0);
    for (let i = 0; i < MAX_APPROVER_NUM; i++) {
      const newApprover = new Account({
        publicKey: approvers.at(i) as PublicKey,
        approvePoints: approverPoints.at(i) as UInt32,
      });

      const root = this.approversRoot.get();
      root.assertEquals(root);
      const equal = Bool(
        (paths.at(i) as ApprovalMerkleWitness).calculateRoot(
          newApprover.hash()
        ) === root
      );
      total.add(approverPoints.at(i) as UInt32);
      if (equal) {
        return total;
      } else {
        return new UInt32(0);
      }
    }
    return new UInt32();
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
  sendAssets(
    proposalWithSigns: ProposalWithSigns,
    approvers: PublicKey[],
    approverPoints: UInt32[],
    paths: ApprovalMerkleWitness[]
  ) {
    let approverHashes = this.approverHashes.get();
    this.approverHashes.assertEquals(approverHashes);
    const approverLen = new UInt32(approvers.length);
    approverLen.assertGreaterThan(proposalWithSigns.proposal.signThreshold);

    let out = Circuit.if(
      new Bool(approverLen === new UInt32(1)),
      this.getWeightOfSigner(
        approvers.at(0) as PublicKey,
        approverPoints.at(0) as UInt32,
        paths.at(0) as ApprovalMerkleWitness
      ),
      this.getWeightOfBatchSigner(approvers, approverPoints, paths)
    );

    out.assertEquals(proposalWithSigns.proposal.signThreshold);

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
