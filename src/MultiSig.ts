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
  AccountUpdate,
  MerkleTree,
  MerkleWitness,
  Permissions,
  Struct,
} from 'snarkyjs';

const doProofs = true;

class MyMerkleWitness extends MerkleWitness(8) {}

class Account extends Struct({
  publicKey: PublicKey,
  votePoints: UInt32,
}) {
  hash(): Field {
    return Poseidon.hash(Account.toFields(this));
  }

  setVotePoints(points: number) {
    return new Account({
      publicKey: this.publicKey,
      votePoints: UInt32.from(points),
    });
  }
}
// we need the initiate tree root in order to tell the contract about our off-chain storage
let initialCommitment: Field = Field(0);

class MultiSigWallet extends SmartContract {
  // Merkle tree of users
  @state(Field) approversRoot = State<Field>();

  deploy(args: {
    approvers: PublicKey[];
    approverPoints: UInt32[];
    approverThreshold: UInt32;
    zkappKey?: PrivateKey | undefined;
    verificationKey?:
      | {
          data: string;
          hash: string | Field;
        }
      | undefined;
  }) {
    super.deploy(args);
    // const merkleWitness = new MyMerkleWitness(8)
    // this.approversRoot.set(this.recursiveMerkleTreeGenerate(args.approvers, args.approverPoints, this.approversRoot, new MyMerkleWitness))
    // this.approverHashes.set(ApproverHashes.createWithPadding(args.approvers));
    // this.approverThreshold.set(args.approverThreshold);
    // this.latestProposalHash.set(Field(0));
  }

  recursiveMerkleTreeGenerate(
    approvers: PublicKey[],
    approverPoints: UInt32[],
    hash: Field,
    path: MyMerkleWitness
  ): Field {
    if (approvers.length == 0) return hash;
    else {
      let approver = approvers.pop();
      let approverPoint = approverPoints.pop();
      // make sure there is the approver at the index
      approver?.isEmpty().assertEquals(false);
      // create a new approver
      const newApprover = new Account({
        publicKey: approver as PublicKey,
        votePoints: approverPoint as UInt32,
      });
      const newApproversRoot = path.calculateRoot(newApprover.hash());

      this.approversRoot.set(newApproversRoot);
      return this.recursiveMerkleTreeGenerate(
        approvers,
        approverPoints,
        hash,
        path
      );
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
}

// // we check that the account is within the committed Merkle Tree
// path.calculateRoot(account.hash()).assertEquals(walletsRoot);
